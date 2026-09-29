// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.forge.client;

import io.github.katyusha8138.mcc2s.common.AgentScanner;
import io.github.katyusha8138.mcc2s.common.ClientVerification;
import io.github.katyusha8138.mcc2s.common.EntrySeed;
import io.github.katyusha8138.mcc2s.common.HashCache;
import io.github.katyusha8138.mcc2s.common.ModScanner;
import io.github.katyusha8138.mcc2s.common.ShaderPackScanner;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.forge.FmlInfo;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import net.minecraft.client.Minecraft;
import net.minecraft.server.packs.repository.Pack;
import net.minecraftforge.fml.loading.FMLPaths;

/** クライアントの構成(Mod・リソースパック・シェーダー・JVM エージェント・mcC2S 自身)を集める。 */
final class ClientCollector {
    private static final HashCache CACHE = new HashCache();

    private ClientCollector() {}

    /** クライアントスレッドで確定させる、有効なリソースパックの参照(ハッシュ計算はワーカーで行う)。 */
    private record PackRef(String id) {}

    static ClientVerification.Collected collect(Set<Scope> requested) throws Exception {
        List<EntrySeed> seeds = new ArrayList<>();
        Set<Scope> reported = EnumSet.noneOf(Scope.class);

        Path self = FmlInfo.selfPath();
        seeds.add(new EntrySeed(EntryKind.SELF, "mcc2s", FmlInfo.selfVersion(), CACHE.sha256(self), Files.isRegularFile(self) ? self : null));

        if (requested.contains(Scope.MODS)) {
            seeds.addAll(ModScanner.scan(FMLPaths.MODSDIR.get(), FmlInfo.loadedMods(), FmlInfo.PLATFORM_MOD_IDS, CACHE));
            reported.add(Scope.MODS);
        }
        if (requested.contains(Scope.JVM_AGENTS)) {
            seeds.addAll(AgentScanner.scan(
                    ManagementFactory.getRuntimeMXBean().getInputArguments(),
                    System.getenv(),
                    Path.of("").toAbsolutePath(),
                    CACHE));
            reported.add(Scope.JVM_AGENTS);
        }
        if (requested.contains(Scope.SHADER_PACKS)) {
            seeds.addAll(ShaderPackScanner.scan(FMLPaths.GAMEDIR.get(), CACHE));
            reported.add(Scope.SHADER_PACKS);
        }
        if (requested.contains(Scope.RESOURCE_PACKS)) {
            seeds.addAll(resourcePacks());
            reported.add(Scope.RESOURCE_PACKS);
        }
        return new ClientVerification.Collected(reported, seeds);
    }

    private static List<EntrySeed> resourcePacks() throws Exception {
        Minecraft mc = Minecraft.getInstance();
        // 有効なパックの一覧はクライアントスレッドで読む
        List<PackRef> packs = mc.submit(() -> {
            List<PackRef> list = new ArrayList<>();
            for (Pack p : mc.getResourcePackRepository().getSelectedPacks()) {
                list.add(new PackRef(p.getId()));
            }
            return list;
        }).get(15, TimeUnit.SECONDS);
        Path packDir = mc.getResourcePackDirectory();

        StringBuilder seen = new StringBuilder();
        List<EntrySeed> out = new ArrayList<>();
        for (PackRef p : packs) {
            seen.append(p.id()).append(' ');
            // 報告するのは「プレイヤーが resourcepacks/ に置いたローカルのパック(ID が file/ で始まる)」だけ。
            // バニラ・機能フラグ・サーバー配布・ワールド同梱は対象外。Mod が提供するパック(mod/<id>, mod_resources)は
            // 中身が Mod の jar ハッシュに含まれるため二重には報告しない(出所の種別では区別できないので ID で判定する)。
            if (!p.id().startsWith("file/")) {
                continue;
            }
            Path path = packDir.resolve(p.id().substring("file/".length()));
            String sha = ModScanner.UNREADABLE_SHA;
            try {
                sha = CACHE.sha256(path);
            } catch (IOException e) {
                // 読めなければゼロのハッシュで報告(隠さない)
            }
            out.add(new EntrySeed(EntryKind.RESOURCE_PACK, p.id(), "", sha, Files.isRegularFile(path) ? path : null));
        }
        FmlInfo.LOG.info("[mcC2S] selected resource packs: " + seen + "-> reporting " + out.size() + " local pack(s)");
        return out;
    }
}
