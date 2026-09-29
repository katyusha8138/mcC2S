// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.forge;

import io.github.katyusha8138.mcc2s.forge.client.ClientReload;
import io.github.katyusha8138.mcc2s.forge.server.ServerCommands;
import io.github.katyusha8138.mcc2s.forge.server.ServerHooks;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.RegisterCommandsEvent;
import net.minecraftforge.event.entity.player.PlayerEvent;
import net.minecraftforge.event.entity.player.PlayerNegotiationEvent;
import net.minecraftforge.event.server.ServerAboutToStartEvent;
import net.minecraftforge.event.server.ServerStoppedEvent;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.fml.loading.FMLEnvironment;

/**
 * mcC2S の Forge 1.20.1 エントリ。
 * <ul>
 *   <li>専用サーバー: ログイン交渉(認証後・ワールド参加前)でクライアントを検証し、完了までワールドに入れない</li>
 *   <li>クライアント: サーバーからチャレンジが届いたときだけ応答する(未導入サーバー・シングルプレイでは何もしない)</li>
 * </ul>
 */
@Mod(McC2S.MOD_ID)
public final class McC2S {
    public static final String MOD_ID = "mcc2s";

    public McC2S() {
        Network.register();
        IEventBus modBus = FMLJavaModLoadingContext.get().getModEventBus();
        if (FMLEnvironment.dist.isDedicatedServer()) {
            MinecraftForge.EVENT_BUS.addListener(ServerHooks::onServerAboutToStart);
            MinecraftForge.EVENT_BUS.addListener(ServerHooks::onServerStopped);
            MinecraftForge.EVENT_BUS.addListener(McC2S::onNegotiation);
            // プレイ中のランダム再検証(参加後に導入されたチートの検知)と管理コマンド
            MinecraftForge.EVENT_BUS.addListener(McC2S::onPlayerLoggedIn);
            MinecraftForge.EVENT_BUS.addListener(McC2S::onPlayerLoggedOut);
            MinecraftForge.EVENT_BUS.addListener(McC2S::onRegisterCommands);
        }
        if (FMLEnvironment.dist.isClient()) {
            // リソースパックの切り替え(リソースの再読み込み)をサーバーに知らせ、即時の再検証を促す
            modBus.addListener(ClientReload::register);
        }
    }

    // ジェネリクスの推論を確実にするため、イベントの型を明示したメソッドを経由する
    private static void onNegotiation(PlayerNegotiationEvent event) {
        ServerHooks.onNegotiation(event);
    }

    private static void onPlayerLoggedIn(PlayerEvent.PlayerLoggedInEvent event) {
        ServerHooks.onPlayerLoggedIn(event);
    }

    private static void onPlayerLoggedOut(PlayerEvent.PlayerLoggedOutEvent event) {
        ServerHooks.onPlayerLoggedOut(event);
    }

    private static void onRegisterCommands(RegisterCommandsEvent event) {
        ServerCommands.register(event);
    }
}
