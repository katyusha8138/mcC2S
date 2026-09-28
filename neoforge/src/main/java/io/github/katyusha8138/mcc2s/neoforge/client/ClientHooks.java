// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge.client;

import io.github.katyusha8138.mcc2s.common.Bindings;
import io.github.katyusha8138.mcc2s.common.ClientVerification;
import io.github.katyusha8138.mcc2s.common.ManifestAssembler;
import io.github.katyusha8138.mcc2s.common.TrustFiles;
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

    /** サーバー→クライアントのチャンク(チャレンジ / 判定)。 */
    public static void handle(VerifyPayload payload, IPayloadContext context) {
        Connection connection = context.connection();
        ClientVerification v = SESSIONS.computeIfAbsent(connection, c -> {
            c.channel().closeFuture().addListener(f -> SESSIONS.remove(c));
            return create(context);
        });
        v.onChunk(payload.data());
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
