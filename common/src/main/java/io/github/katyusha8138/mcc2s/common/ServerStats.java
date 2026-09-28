// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** 検証の集計(`/mcc2s status` 用)。サーバー起動からのカウンタ。 */
public final class ServerStats {
    public enum Counter {
        /** 参加時の検証に成功(audit で違反があっても通した場合は AUDIT_ALLOWED)。 */
        VERIFIED,
        AUDIT_ALLOWED,
        DENIED,
        /** ハンドシェイク自体の失敗(認証失敗・不正なデータなど)。 */
        HANDSHAKE_FAILED,
        TIMEOUT,
        /** クライアントに mcC2S が無かった。 */
        MISSING_MOD,
        /** プレイ中の再検証に成功。 */
        REVERIFIED,
        /** プレイ中の再検証で切断した。 */
        REVERIFY_KICKED
    }

    private final Map<Counter, AtomicLong> counters = new EnumMap<>(Counter.class);

    public ServerStats() {
        for (Counter c : Counter.values()) {
            counters.put(c, new AtomicLong());
        }
    }

    public void inc(Counter c) {
        counters.get(c).incrementAndGet();
    }

    public long get(Counter c) {
        return counters.get(c).get();
    }

    public String summary() {
        StringBuilder sb = new StringBuilder();
        for (Counter c : Counter.values()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(c.name().toLowerCase(java.util.Locale.ROOT)).append('=').append(get(c));
        }
        return sb.toString();
    }
}
