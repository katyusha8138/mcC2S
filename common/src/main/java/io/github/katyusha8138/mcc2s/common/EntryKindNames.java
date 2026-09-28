// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.util.List;
import java.util.Locale;

/** コマンド・CLI で使う項目種別の名前(`resource-pack` など)。SELF は許可リストを持たないので含まない。 */
public final class EntryKindNames {
    public static final List<String> NAMES =
            List.of("mod", "library", "resource-pack", "shader-pack", "agent", "other-code");

    private EntryKindNames() {}

    /** @throws IllegalArgumentException 不明な名前 */
    public static EntryKind parse(String name) {
        switch (name.toLowerCase(Locale.ROOT)) {
            case "mod":
                return EntryKind.MOD;
            case "library":
                return EntryKind.LIBRARY;
            case "resource-pack":
                return EntryKind.RESOURCE_PACK;
            case "shader-pack":
                return EntryKind.SHADER_PACK;
            case "agent":
                return EntryKind.AGENT;
            case "other-code":
                return EntryKind.OTHER_CODE;
            default:
                throw new IllegalArgumentException("unknown kind '" + name + "' (one of " + NAMES + ")");
        }
    }
}
