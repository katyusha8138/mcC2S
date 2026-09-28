// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge.client;

import net.minecraft.server.packs.resources.ResourceManagerReloadListener;
import net.neoforged.neoforge.client.event.RegisterClientReloadListenersEvent;

/** リソースの再読み込み(リソースパックの切り替え等)を検知して、サーバーに再検証を促す。 */
public final class ClientReload {
    private ClientReload() {}

    public static void register(RegisterClientReloadListenersEvent event) {
        event.registerReloadListener((ResourceManagerReloadListener) manager -> ClientHooks.onResourcesReloaded());
    }
}
