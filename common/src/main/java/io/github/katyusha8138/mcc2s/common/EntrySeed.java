// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.nio.file.Path;

/**
 * 走査結果の 1 項目(まだ測定証明が付いていない)。
 *
 * @param file 測定証明の計算に使う実ファイル。フォルダや実体の無い項目は null
 */
public record EntrySeed(EntryKind kind, String id, String version, String sha256, Path file) {
    public Entry toEntry() {
        return new Entry(
                kind, Sanitize.text(id, Entry.MAX_ID_CHARS), Sanitize.text(version, Entry.MAX_VERSION_CHARS), sha256);
    }
}
