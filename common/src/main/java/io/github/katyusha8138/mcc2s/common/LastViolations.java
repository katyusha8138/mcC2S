// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * プレイヤーごとの直近の違反報告(`/mcc2s whitelist add <player>` が参照する)。
 * オフラインモードでは任意の名前で大量に接続できるため、保持数に上限を設ける。
 */
public final class LastViolations {
    private static final int MAX_ENTRIES = 256;

    private final Map<String, ViolationReport> byPlayer = new LinkedHashMap<>(16, 0.75f, false) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, ViolationReport> eldest) {
            return size() > MAX_ENTRIES;
        }
    };

    public synchronized void record(ViolationReport report) {
        String key = report.playerName().toLowerCase(Locale.ROOT);
        byPlayer.remove(key); // 挿入順を更新して「最近のもの」を残す
        byPlayer.put(key, report);
    }

    public synchronized Optional<ViolationReport> get(String playerName) {
        return Optional.ofNullable(byPlayer.get(playerName.toLowerCase(Locale.ROOT)));
    }

    public synchronized int size() {
        return byPlayer.size();
    }
}
