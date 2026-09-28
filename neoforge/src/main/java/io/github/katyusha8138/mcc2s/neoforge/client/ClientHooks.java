// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge.client;

import io.github.katyusha8138.mcc2s.common.Bindings;
import io.github.katyusha8138.mcc2s.common.ClientVerification;
import io.github.katyusha8138.mcc2s.common.ManifestAssembler;
import io.github.katyusha8138.mcc2s.common.TrustFiles;
import io.github.katyusha8138.mcc2s.core.handshake.Fragmenter;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.neoforge.FmlInfo;
import io.github.katyusha8138.mcc2s.neoforge.VerifyPayload;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import net.minecraft.SharedConstants;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientPacketListener;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.neoforged.fml.loading.FMLLoader;
import net.neoforged.fml.loading.FMLPaths;
import net.neoforged.neoforge.network.handling.IPayloadContext;

/**
 * クライアント側の配線。サーバーからチャレンジが届いたときだけ動く。
 * サーバーが mcC2S を導入していない場合・シングルプレイでは、このクラスは一度も呼ばれない。
 */
public final class ClientHooks {
    private static final Map<Connection, ClientVerification> SESSIONS = new ConcurrentHashMap<>();
    private static final ExecutorService WORKER = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "mcC2S-client");
        t.setDaemon(true);
        return t;
    });
    private static final SecureRandom RANDOM = new SecureRandom();

    private ClientHooks() {}

    /**
     * サーバー→クライアントのチャンク(チャレンジ / 判定)。
     * 新しいチャレンジの先頭チャンクが来るたびに検証を最初から作り直す(参加時の検証と、プレイ中の再検証の両方)。
     */
    public static void handle(VerifyPayload payload, IPayloadContext context) {
        Connection connection = context.connection();
        byte[] data = payload.data();
        ClientVerification v;
        if (isChallengeStart(data)) {
            v = create(context);
            if (SESSIONS.put(connection, v) == null) {
                connection.channel().closeFuture().addListener(f -> SESSIONS.remove(connection));
            }
        } else {
            v = SESSIONS.get(connection);
            if (v == null) {
                return; // チャレンジ無しに届いたチャンクは無視する
            }
        }
        v.onChunk(data);
    }

    private static boolean isChallengeStart(byte[] data) {
        try {
            Fragmenter.Chunk c = Fragmenter.Chunk.decode(data);
            return c.type() == Fragmenter.TYPE_CHALLENGE && c.index() == 0;
        } catch (WireException e) {
            return false;
        }
    }

    /**
     * リソースが再読み込みされた(リソースパックの切り替えなど)。mcC2S 導入サーバーに接続中なら、
     * 次の定期検証を待たずに再検証してほしいとサーバーに通知する(サーバー側で連打は抑制される)。
     */
    static void onResourcesReloaded() {
        ClientPacketListener listener = Minecraft.getInstance().getConnection();
        if (listener == null || !SESSIONS.containsKey(listener.getConnection()) || !listener.hasChannel(VerifyPayload.TYPE)) {
            return; // シングルプレイ・未導入サーバー・接続前の初回読み込みでは何もしない
        }
        listener.send(new VerifyPayload(new Fragmenter.Chunk(Fragmenter.TYPE_REVERIFY_REQUEST, 0, 1, new byte[0]).encode()));
    }

    private static ClientVerification create(IPayloadContext context) {
        String name = Minecraft.getInstance().getUser().getName();
        Path trustDir = FMLPaths.CONFIGDIR.get().resolve("mcc2s").resolve("trust");
        var env = new ManifestAssembler.Env(
                SharedConstants.getCurrentVersion().getName(),
                "neoforge",
                FMLLoader.versionInfo().neoForgeVersion(),
                FmlInfo.selfVersion());

        return new ClientVerification(
                () -> TrustFiles.load(trustDir, FmlInfo.LOG),
                Bindings.player(name),
                ClientCollector::collect,
                env,
                new ClientVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {
                        context.reply(new VerifyPayload(chunk));
                    }

                    @Override
                    public void abort(String message) {
                        Minecraft.getInstance().execute(() -> context.disconnect(Component.literal(message)));
                    }
                },
                WORKER,
                RANDOM,
                FmlInfo.LOG);
    }
}
