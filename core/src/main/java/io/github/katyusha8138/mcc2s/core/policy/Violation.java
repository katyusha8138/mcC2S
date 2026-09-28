// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;

/**
 * 1 件の違反。
 *
 * @param kind 対象の種別(範囲不足など特定の項目に紐づかない場合は null)
 * @param id 対象の ID(範囲不足では範囲名)
 */
public record Violation(ViolationCode code, EntryKind kind, String id, String version, String sha256, String detail) {
    @Override
    public String toString() {
        return code + (kind == null ? "" : " " + kind) + " [" + id + (version.isEmpty() ? "" : "@" + version) + "]"
                + (sha256.isEmpty() ? "" : " sha256=" + sha256) + (detail.isEmpty() ? "" : " (" + detail + ")");
    }
}
