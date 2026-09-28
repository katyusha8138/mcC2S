// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge.server;

import io.github.katyusha8138.mcc2s.common.Messages;
import io.github.katyusha8138.mcc2s.common.Sanitize;
import io.github.katyusha8138.mcc2s.common.ServerRuntime;
import io.github.katyusha8138.mcc2s.common.ServerVerification;
import io.github.katyusha8138.mcc2s.neoforge.FmlInfo;
import io.github.katyusha8138.mcc2s.neoforge.VerifyPayload;
import java.net.SocketAddress;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerConfigurationPacketListenerImpl;
import net.neoforged.fml.loading.FMLPaths;
import net.neoforged.neoforge.event.server.ServerAboutToStartEvent;
import net.neoforged.neoforge.event.server.ServerStoppedEvent;
import net.neoforged.neoforge.network.configuration.ICustomConfigurationTask;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import net.neoforged.neoforge.server.ServerLifecycleHooks;

/**
 * 専用サーバー側の配線。ログイン認証後・プレイ開始前の「設定フェーズ」に検証タスクを差し込み、
 * 検証が完了するまでプレイヤーをワールドに入れない。
 */
public final class ServerHooks {
    private static final ConfigurationTask.Type TASK_TYPE = new ConfigurationTask.Type("mcc2s:verify");
    private static final Map<Connection, ServerVerification> SESSIONS = new ConcurrentHashMap<>();
    private static volatile ServerRuntime runtime;

    private ServerHooks() {}

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
            runtime = ServerRuntime.start(inputs, new SecureRandom());
        } catch (Exception e) {
            throw new IllegalStateException("mcC2S could not start: " + e.getMessage()
                    + " (fix config/mcc2s/ and restart; the server is not started without verification)", e);
        }
    }

    public static void onServerStopped(ServerStoppedEvent event) {
        ServerRuntime rt = runtime;
        runtime = null;
        SESSIONS.clear();
        if (rt != null) {
            rt.close();
        }
    }

    /** 接続ごとに 1 回、設定フェーズのタスク一覧を集めるときに呼ばれる。 */
    public static void onConfigurationTasks(RegisterConfigurationTasksEvent event) {
        var listener = event.getListener();
        // シングルプレイ・LAN 公開の統合サーバーの内部接続では何もしない
        if (listener.getConnection().isMemoryConnection() || !(listener instanceof ServerConfigurationPacketListenerImpl impl)) {
            return;
        }
        event.register(new VerifyTask(impl));
    }

    /** クライアント→サーバーのチャンク。 */
    public static void handle(VerifyPayload payload, IPayloadContext context) {
        ServerVerification v = SESSIONS.get(context.connection());
        if (v != null) {
            v.onChunk(payload.data());
        }
        // 要求していない接続からのチャンクは無視する
    }

    private static final class VerifyTask implements ICustomConfigurationTask {
        private final ServerConfigurationPacketListenerImpl listener;

        VerifyTask(ServerConfigurationPacketListenerImpl listener) {
            this.listener = listener;
        }

        @Override
        public Type type() {
            return TASK_TYPE;
        }

        @Override
        public void run(java.util.function.Consumer<net.minecraft.network.protocol.common.custom.CustomPacketPayload> sender) {
            ServerRuntime rt = runtime;
            Connection connection = listener.getConnection();
            MinecraftServer server = ServerLifecycleHooks.getCurrentServer();
            if (rt == null || server == null) {
                listener.disconnect(Component.literal(Messages.busy()));
                return;
            }

            var profile = listener.getOwner();
            var player = new ServerVerification.Player(profile.getName(), profile.getId(), describe(connection.getRemoteAddress()));
            var verification = new ServerVerification(rt.context(), player, new ServerVerification.Transport() {
                @Override
                public void send(byte[] chunk) {
                    listener.send(new VerifyPayload(chunk));
                }

                @Override
                public void kick(String message) {
                    // 設定フェーズのリスナーはメインスレッドで扱う
                    server.execute(() -> {
                        if (connection.isConnected()) {
                            listener.disconnect(Component.literal(message));
                        }
                    });
                }

                @Override
                public void allow() {
                    server.execute(() -> {
                        if (connection.isConnected()) {
                            listener.finishCurrentTask(TASK_TYPE);
                        }
                    });
                }
            });

            SESSIONS.put(connection, verification);
            connection.channel().closeFuture().addListener(f -> SESSIONS.remove(connection));

            // mcC2S を持たないクライアント(バニラ・他ローダー・未導入)はチャンネルが無い
            if (!listener.hasChannel(VerifyPayload.TYPE)) {
                verification.onClientLacksMod();
                return;
            }
            rt.timer().schedule(verification::onTimeout, verification.policy().handshakeTimeoutSeconds(), TimeUnit.SECONDS);
            verification.start();
        }

        private static String describe(SocketAddress address) {
            return address == null ? "unknown" : address.toString();
        }
    }
}
