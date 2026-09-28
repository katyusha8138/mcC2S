// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import java.nio.file.Path;
import java.util.List;

/** ローダーが Mod として読み込んだファイル(FML の ModFile 等)。ローダーアダプタが作る。 */
public record LoadedMod(Path path, List<String> modIds, String version) {
    public LoadedMod {
        modIds = List.copyOf(modIds);
    }
}
