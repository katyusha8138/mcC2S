// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge;

import io.github.katyusha8138.mcc2s.neoforge.client.ClientHooks;
import io.github.katyusha8138.mcc2s.neoforge.server.ServerHooks;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.loading.FMLEnvironment;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.server.ServerAboutToStartEvent;
import net.neoforged.neoforge.event.server.ServerStoppedEvent;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.handling.DirectionalPayloadHandler;
import net.neoforged.neoforge.network.registration.HandlerThread;

/**
 * mcC2S の NeoForge 1.21.1 エントリ。
 * <ul>
 *   <li>専用サーバー: ログイン認証後・プレイ開始前の設定フェーズでクライアントを検証する</li>
 *   <li>クライアント: サーバーからチャレンジが届いたときだけ応答する(未導入サーバー・シングルプレイでは何もしない)</li>
 * </ul>
 * ペイロードは optional で登録する。これにより「mcC2S 未導入のサーバー」にも mcC2S 導入クライアントが参加でき、
 * 「mcC2S 導入サーバー」への未導入クライアントはサーバー側の検証タスクが拒否する。
 */
@Mod(McC2S.MOD_ID)
public final class McC2S {
    public static final String MOD_ID = "mcc2s";

    public McC2S(IEventBus modBus) {
        modBus.addListener(McC2S::registerPayloads);
        if (FMLEnvironment.dist.isDedicatedServer()) {
            modBus.addListener(RegisterConfigurationTasksEvent.class, ServerHooks::onConfigurationTasks);
            NeoForge.EVENT_BUS.addListener(ServerAboutToStartEvent.class, ServerHooks::onServerAboutToStart);
            NeoForge.EVENT_BUS.addListener(ServerStoppedEvent.class, ServerHooks::onServerStopped);
        }
    }

    private static void registerPayloads(RegisterPayloadHandlersEvent event) {
        event.registrar("1")
                .optional()
                // 既定ではメインスレッドで処理される。ハッシュ計算などでゲームを止めないよう、ネットワークスレッドで受ける。
                .executesOn(HandlerThread.NETWORK)
                .configurationBidirectional(
                        VerifyPayload.TYPE,
                        VerifyPayload.CODEC,
                        new DirectionalPayloadHandler<>(ClientHooks::handle, ServerHooks::handle));
    }
}
