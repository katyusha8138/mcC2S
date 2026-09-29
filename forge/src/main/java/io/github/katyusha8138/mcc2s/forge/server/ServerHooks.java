// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.forge.server;

import com.mojang.authlib.GameProfile;
import io.github.katyusha8138.mcc2s.common.Messages;
import io.github.katyusha8138.mcc2s.common.Reverifier;
import io.github.katyusha8138.mcc2s.common.Sanitize;
import io.github.katyusha8138.mcc2s.common.ServerRuntime;
import io.github.katyusha8138.mcc2s.common.ServerVerification;
import io.github.katyusha8138.mcc2s.core.handshake.Fragmenter;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.forge.FmlInfo;
import io.github.katyusha8138.mcc2s.forge.Network;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import net.minecraftforge.event.entity.player.PlayerEvent;
import net.minecraftforge.event.entity.player.PlayerNegotiationEvent;
import net.minecraftforge.event.server.ServerAboutToStartEvent;
import net.minecraftforge.event.server.ServerStoppedEvent;
import net.minecraftforge.fml.loading.FMLPaths;
import net.minecraftforge.network.ConnectionData;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.NetworkHooks;
import net.minecraftforge.network.PacketDistributor;
import net.minecraftforge.server.ServerLifecycleHooks;

/**
 * 専用サーバー側の配線。ログイン交渉({@link PlayerNegotiationEvent})に Future を登録し、検証が完了するまで
 * プレイヤーをワールドに入れない。
 */
public final class ServerHooks {
    private static final Map<Connection, ServerVerification> SESSIONS = new ConcurrentHashMap<>();
    /** 「構成が変わった」通知による再検証の最小間隔(連打で負荷が上がらないように)。 */
    private static final long REVERIFY_MIN_GAP_MILLIS = 10_000;
    /**
     * バニラのログインは 30 秒(600 tick、認証・FML の同期を含む)で「ログインに時間がかかりすぎ」として切られる。
     * 検証はそれより先に、mcC2S の案内付きで打ち切る。
     */
    private static final int MAX_LOGIN_SECONDS = 20;
    /** クライアントの Mod 一覧(FML ハンドシェイクの返信)が届くのを待つ間隔。 */
    private static final long CHANNEL_POLL_MILLIS = 50;

    private static volatile ServerRuntime runtime;
    private static volatile Reverifier<UUID> reverifier;

    private ServerHooks() {}

    public static ServerRuntime runtime() {
        return runtime;
    }

    /**
     * TCP リスナーの起動より前に発火するため、最初の接続が来る時点で必ず初期化済みになる。
     * 失敗したらサーバーを起動させない(検証なしで公開してしまう事故を避ける = 安全側に倒す)。
     */
    public static void onServerAboutToStart(ServerAboutToStartEvent event) {
        MinecraftServer server = event.getServer();
        if (!server.isDedicatedServer()) {
            return;
        }
        try {
            var game = FMLPaths.GAMEDIR.get();
            var inputs = new ServerRuntime.Inputs(
                    FMLPaths.CONFIGDIR.get().resolve("mcc2s"),
                    FMLPaths.MODSDIR.get(),
                    game.resolve("logs").resolve("mcc2s"),
                    FmlInfo.loadedMods(),
                    FmlInfo.PLATFORM_MOD_IDS,
                    FmlInfo.selfPath(),
                    FmlInfo.selfVersion(),
                    "mcC2S: " + Sanitize.text(server.getMotd(), 48),
                    FmlInfo.LOG);
            ServerRuntime rt = ServerRuntime.start(inputs, new SecureRandom());
            runtime = rt;
            // 間隔は再検証のたびに現在のポリシーから読む(/mcc2s reload が次回から反映される)
            reverifier = new Reverifier<>(
                    rt.timer(), new Random(), () -> Reverifier.intervalsOf(rt.context().policy()), REVERIFY_MIN_GAP_MILLIS);
        } catch (Exception e) {
            throw new IllegalStateException("mcC2S could not start: " + e.getMessage()
                    + " (fix config/mcc2s/ and restart; the server is not started without verification)", e);
        }
    }

    public static void onServerStopped(ServerStoppedEvent event) {
        ServerRuntime rt = runtime;
        Reverifier<UUID> rv = reverifier;
        runtime = null;
        reverifier = null;
        SESSIONS.clear();
        if (rv != null) {
            rv.stopAll();
        }
        if (rt != null) {
            rt.close();
        }
    }

    // ---- ログイン時の検証 ----

    /**
     * 接続ごとに 1 回、ログイン交渉の開始時に呼ばれる(サーバースレッド)。
     * ここで登録した Future が完了するまで、FML はログインを先へ進めない。Future は検証を通ったときだけ完了させ、
     * 拒否・タイムアウトでは完了させない(切断されるので、接続ごと破棄される = 安全側)。
     */
    public static void onNegotiation(PlayerNegotiationEvent event) {
        Connection connection = event.getConnection();
        // シングルプレイ・LAN 公開の統合サーバーの内部接続では何もしない
        if (connection.isMemoryConnection()) {
            return;
        }
        CompletableFuture<Void> gate = new CompletableFuture<>();
        event.enqueueWork(gate);

        ServerRuntime rt = runtime;
        MinecraftServer server = ServerLifecycleHooks.getCurrentServer();
        if (rt == null || server == null) {
            disconnectLogin(server, connection, Messages.busy());
            return;
        }

        GameProfile profile = event.getProfile();
        // オフラインモードでは、ログイン交渉の時点ではまだ UUID が無い(参加処理で割り当てられる)。
        // ログ・違反記録用に、バニラがオフラインで割り当てるのと同じ規則の UUID を使う(接続の束縛はログイン名なので影響しない)。
        UUID id = profile.getId() != null ? profile.getId() : UUIDUtil.createOfflinePlayerUUID(profile.getName());
        var player = new ServerVerification.Player(profile.getName(), id, describe(connection.getRemoteAddress()));
        var verification = new ServerVerification(rt.context(), player, new ServerVerification.Transport() {
            @Override
            public void send(byte[] chunk) {
                Network.sendLoginQuery(connection, chunk);
            }

            @Override
            public void kick(String message) {
                disconnectLogin(server, connection, message);
            }

            @Override
            public void allow() {
                gate.complete(null);
            }
        });

        SESSIONS.put(connection, verification);
        connection.channel().closeFuture().addListener(f -> SESSIONS.remove(connection));

        int timeoutSeconds = Math.min(verification.policy().handshakeTimeoutSeconds(), MAX_LOGIN_SECONDS);
        rt.timer().schedule(verification::onTimeout, timeoutSeconds, TimeUnit.SECONDS);
        awaitClientMods(rt.timer(), connection, verification, System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds));
    }

    /**
     * クライアントが mcC2S を持っているかは、FML ハンドシェイクでクライアントの Mod/チャンネル一覧が届くまで分からない。
     * 届くまで待ち、持っていれば検証を始め、無ければ(バニラ・他ローダー・未導入)拒否する。
     */
    private static void awaitClientMods(
            ScheduledExecutorService timer, Connection connection, ServerVerification verification, long deadlineNanos) {
        if (!connection.isConnected() || !SESSIONS.containsKey(connection)) {
            return;
        }
        if (NetworkHooks.isVanillaConnection(connection)) {
            verification.onClientLacksMod();
            return;
        }
        ConnectionData data = NetworkHooks.getConnectionData(connection);
        if (data == null) {
            if (System.nanoTime() < deadlineNanos) {
                timer.schedule(() -> awaitClientMods(timer, connection, verification, deadlineNanos), CHANNEL_POLL_MILLIS, TimeUnit.MILLISECONDS);
            }
            return; // 期限を過ぎたら verification.onTimeout が切断する
        }
        if (!data.getChannels().containsKey(Network.CHANNEL_ID)) {
            verification.onClientLacksMod();
            return;
        }
        verification.start();
    }

    /** ログイン中の接続を、理由付きで切る。サーバースレッドで行う。 */
    private static void disconnectLogin(MinecraftServer server, Connection connection, String message) {
        Runnable action = () -> {
            if (!connection.isConnected()) {
                return;
            }
            Component reason = Component.literal(message);
            if (connection.getPacketListener() instanceof ServerLoginPacketListenerImpl login) {
                login.disconnect(reason); // ログイン用の切断パケット(理由付き)を送ってから閉じる
            } else {
                connection.disconnect(reason);
            }
        };
        if (server != null) {
            server.execute(action);
        } else {
            action.run();
        }
    }

    // ---- プレイ中の再検証 ----

    /** 参加(=検証通過)後、ランダムな間隔での再検証を予約する。 */
    public static void onPlayerLoggedIn(PlayerEvent.PlayerLoggedInEvent event) {
        Reverifier<UUID> rv = reverifier;
        if (rv == null || !(event.getEntity() instanceof ServerPlayer player) || player.connection.connection.isMemoryConnection()) {
            return;
        }
        rv.start(player.getUUID(), () -> startRecheck(player));
    }

    public static void onPlayerLoggedOut(PlayerEvent.PlayerLoggedOutEvent event) {
        Reverifier<UUID> rv = reverifier;
        if (rv != null) {
            rv.stop(event.getEntity().getUUID());
        }
    }

    /** timer スレッドから呼ばれる。実際の処理はサーバースレッドで行う。 */
    private static void startRecheck(ServerPlayer player) {
        ServerRuntime rt = runtime;
        MinecraftServer server = ServerLifecycleHooks.getCurrentServer();
        Reverifier<UUID> rv = reverifier;
        if (rt == null || server == null || rv == null) {
            return;
        }
        server.execute(() -> {
            var listener = player.connection;
            Connection connection = listener.connection;
            UUID id = player.getUUID();
            if (!connection.isConnected()) {
                rv.stop(id);
                return;
            }
            var profile = player.getGameProfile();
            var who = new ServerVerification.Player(profile.getName(), id, describe(connection.getRemoteAddress()));
            var verification = new ServerVerification(rt.context(), who, new ServerVerification.Transport() {
                @Override
                public void send(byte[] chunk) {
                    Network.CHANNEL.send(PacketDistributor.PLAYER.with(() -> player), new Network.VerifyMessage(chunk));
                }

                @Override
                public void kick(String message) {
                    rv.stop(id);
                    server.execute(() -> {
                        if (connection.isConnected()) {
                            listener.disconnect(Component.literal(message));
                        }
                    });
                }

                @Override
                public void allow() {
                    rv.completed(id);
                }
            }, true);

            SESSIONS.put(connection, verification);
            if (!Network.CHANNEL.isRemotePresent(connection)) {
                verification.onClientLacksMod();
                return;
            }
            rt.timer().schedule(verification::onTimeout, verification.policy().handshakeTimeoutSeconds(), TimeUnit.SECONDS);
            verification.start();
        });
    }

    /** クライアント→サーバーのチャンク(ログイン中・プレイ中共通)。ネットワークスレッドで呼ばれる。 */
    public static void handle(byte[] data, NetworkEvent.Context context) {
        // プレイ中にクライアントが「構成が変わった」と通知してきた(リソースパックの切替など)
        if (context.getDirection() == NetworkDirection.PLAY_TO_SERVER && isReverifyRequest(data)) {
            Reverifier<UUID> rv = reverifier;
            ServerPlayer sender = context.getSender();
            if (rv != null && sender != null) {
                rv.requestSoon(sender.getUUID());
            }
            return;
        }
        ServerVerification v = SESSIONS.get(context.getNetworkManager());
        if (v != null) {
            v.onChunk(data);
        }
        // 要求していない接続からのチャンクは無視する
    }

    private static boolean isReverifyRequest(byte[] data) {
        try {
            return Fragmenter.Chunk.decode(data).type() == Fragmenter.TYPE_REVERIFY_REQUEST;
        } catch (WireException e) {
            return false; // 不正なデータはセッション側が検証して切断する
        }
    }

    private static String describe(SocketAddress address) {
        return address == null ? "unknown" : address.toString();
    }
}
