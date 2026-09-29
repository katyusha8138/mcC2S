// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.forge;

import com.mojang.logging.LogUtils;
import io.github.katyusha8138.mcc2s.common.LoadedMod;
import io.github.katyusha8138.mcc2s.common.Log;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import net.minecraftforge.fml.ModList;
import net.minecraftforge.fml.loading.LoadingModList;
import net.minecraftforge.fml.loading.moddiscovery.ModFileInfo;
import net.minecraftforge.forgespi.language.IModInfo;
import org.slf4j.Logger;

/** FML(モードローダー)から、common が必要とする情報を取り出す。 */
public final class FmlInfo {
    /** クライアントとサーバーでファイルが異なる(パッチ済みクライアント jar 等)ため比較しないプラットフォーム Mod。 */
    public static final Set<String> PLATFORM_MOD_IDS = Set.of("minecraft", "forge");

    private static final Logger SLF4J = LogUtils.getLogger();

    public static final Log LOG = new Log() {
        @Override
        public void info(String message) {
            SLF4J.info(message);
        }

        @Override
        public void warn(String message) {
            SLF4J.warn(message);
        }

        @Override
        public void error(String message, Throwable cause) {
            SLF4J.error(message, cause);
        }
    };

    private FmlInfo() {}

    /** FML が読み込んだ Mod ファイル(JarJar の内側は親ファイルに含まれるので common 側で除外される)。 */
    public static List<LoadedMod> loadedMods() {
        List<LoadedMod> out = new ArrayList<>();
        for (ModFileInfo info : LoadingModList.get().getModFiles()) {
            List<String> ids = new ArrayList<>();
            String version = "";
            for (IModInfo mod : info.getMods()) {
                ids.add(mod.getModId());
                if (version.isEmpty()) {
                    version = mod.getVersion().toString();
                }
            }
            out.add(new LoadedMod(info.getFile().getFilePath(), ids, version));
        }
        return out;
    }

    /** mcC2S 自身のファイル(本番では jar、開発環境ではクラスフォルダ)。 */
    public static Path selfPath() {
        return ModList.get().getModFileById(McC2S.MOD_ID).getFile().getFilePath();
    }

    public static String selfVersion() {
        return ModList.get().getModContainerById(McC2S.MOD_ID)
                .map(c -> c.getModInfo().getVersion().toString())
                .orElse("unknown");
    }
}
