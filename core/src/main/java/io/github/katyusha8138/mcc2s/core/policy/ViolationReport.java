// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** サーバーコンソール/ログファイルに出す違反報告。ログ偽装を防ぐため出力時に必ずエスケープする。 */
public final class ViolationReport {
    private final Instant time;
    private final String playerName;
    private final UUID playerId;
    private final String remoteAddress;
    private final byte[] refId;
    private final ServerVerdict.Status action;
    private final List<Violation> violations;

    public ViolationReport(
            Instant time,
            String playerName,
            UUID playerId,
            String remoteAddress,
            byte[] refId,
            ServerVerdict.Status action,
            List<Violation> violations) {
        this.time = time;
        this.playerName = playerName;
        this.playerId = playerId;
        this.remoteAddress = remoteAddress;
        this.refId = refId.clone();
        this.action = action;
        this.violations = new ArrayList<>(violations);
    }

    public Instant time() {
        return time;
    }

    public String playerName() {
        return playerName;
    }

    public UUID playerId() {
        return playerId;
    }

    public ServerVerdict.Status action() {
        return action;
    }

    public List<Violation> violations() {
        return new ArrayList<>(violations);
    }

    /** プレイヤーに見せる参照コード(例: {@code MC2S-1A2B3C4D5E6F7A8B})。ログの行と突き合わせられる。 */
    public String refCode() {
        return "MC2S-" + Digests.hex(refId).toUpperCase(java.util.Locale.ROOT);
    }

    public List<String> consoleLines() {
        List<String> lines = new ArrayList<>();
        lines.add("[mcC2S] " + action + " " + escape(playerName) + " (" + playerId + ") from " + escape(remoteAddress)
                + " ref=" + refCode() + " violations=" + violations.size());
        for (Violation v : violations) {
            lines.add("[mcC2S]   - " + escape(v.toString()));
        }
        return lines;
    }

    /** 1 行 1 レコードの JSON(JSON Lines)。 */
    public String toJsonLine() {
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"time\":").append(quote(time.toString()))
                .append(",\"ref\":").append(quote(refCode()))
                .append(",\"action\":").append(quote(action.name()))
                .append(",\"player\":").append(quote(playerName))
                .append(",\"uuid\":").append(quote(playerId.toString()))
                .append(",\"address\":").append(quote(remoteAddress))
                .append(",\"violations\":[");
        for (int i = 0; i < violations.size(); i++) {
            Violation v = violations.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"code\":").append(quote(v.code().name()))
                    .append(",\"kind\":").append(v.kind() == null ? "null" : quote(v.kind().name()))
                    .append(",\"id\":").append(quote(v.id()))
                    .append(",\"version\":").append(quote(v.version()))
                    .append(",\"sha256\":").append(quote(v.sha256()))
                    .append(",\"detail\":").append(quote(v.detail()))
                    .append('}');
        }
        return sb.append("]}").toString();
    }

    /** 制御文字・改行を可視化して、ログ行の偽造や端末エスケープの注入を防ぐ。 */
    static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || c == ' ' || c == ' ') {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                default:
                    if (c < 0x20 || c == 0x7F || c == ' ' || c == ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }
}
