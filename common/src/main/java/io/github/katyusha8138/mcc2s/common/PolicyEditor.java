// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.AllowEntry;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfigException;
import io.github.katyusha8138.mcc2s.core.policy.TomlPolicyLoader;
import io.github.katyusha8138.mcc2s.core.policy.Violation;
import io.github.katyusha8138.mcc2s.core.policy.ViolationCode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * `policy.toml` の末尾にホワイトリスト項目({@code [[mods.allow]]} など)を追記する(`/mcc2s whitelist add` 用)。
 * <ul>
 *   <li>既存のコメント・書式は一切変えない(追記のみ)</li>
 *   <li>追記後の内容を必ずパースして検証し、壊れる場合は何も書き込まない</li>
 *   <li>クライアント由来の文字列は TOML 文字列として厳密にエスケープする(設定の注入を防ぐ)</li>
 * </ul>
 */
public final class PolicyEditor {
    public record Added(EntryKind kind, String id, String version, String sha256) {}

    public record Result(List<Added> added, List<String> skipped) {}

    private PolicyEditor() {}

    /** 違反のうち、管理者が許可できるもの(未許可/ハッシュ違い + 実在するハッシュ)を許可リストに追加する。 */
    public static Result approve(Path policyFile, List<Violation> violations, String note, Clock clock)
            throws IOException, PolicyConfigException {
        String original = Files.readString(policyFile, StandardCharsets.UTF_8);
        PolicyConfig current = TomlPolicyLoader.parse(original);

        Map<String, Violation> candidates = new LinkedHashMap<>();
        List<String> skipped = new ArrayList<>();
        for (Violation v : violations) {
            String label = v.kind() + " " + v.id();
            if (v.kind() == null || v.kind() == EntryKind.SELF) {
                skipped.add(label + " (not approvable)");
            } else if (v.code() != ViolationCode.NOT_ALLOWED && v.code() != ViolationCode.HASH_MISMATCH) {
                skipped.add(label + " (" + v.code() + " cannot be fixed by an allow entry)");
            } else if (!Digests.isSha256Hex(v.sha256()) || v.sha256().equals(ModScanner.UNREADABLE_SHA)) {
                skipped.add(label + " (file could not be read on the client)");
            } else if (alreadyAllowed(current, v.kind(), v.sha256())) {
                skipped.add(label + " (already allowed)");
            } else {
                candidates.putIfAbsent(v.kind() + "|" + v.sha256(), v);
            }
        }
        if (candidates.isEmpty()) {
            return new Result(List.of(), skipped);
        }

        String date = LocalDate.now(clock).toString();
        StringBuilder add = new StringBuilder();
        if (!original.endsWith("\n")) {
            add.append('\n');
        }
        List<Added> added = new ArrayList<>();
        for (Violation v : candidates.values()) {
            add.append('\n').append(snippet(v.kind(), v.id(), v.version(), v.sha256(), note + " " + date));
            added.add(new Added(v.kind(), v.id(), v.version(), v.sha256()));
        }

        String updated = original + add;
        TomlPolicyLoader.parse(updated); // 壊れる/矛盾する場合はここで例外(ファイルは変更されない)
        writeAtomic(policyFile, updated);
        return new Result(added, skipped);
    }

    /** 種別とハッシュを直接指定して許可する(`/mcc2s whitelist addhash`)。 */
    public static Result approveHash(Path policyFile, EntryKind kind, String sha256, String id, String note, Clock clock)
            throws IOException, PolicyConfigException {
        return approve(
                policyFile, List.of(new Violation(ViolationCode.NOT_ALLOWED, kind, id, "", sha256, "")), note, clock);
    }

    /**
     * 許可項目 1 件分の TOML 断片(コメント行 + テーブル)。クライアント由来の文字列は必ずエスケープされる。
     * `mcc2s-cli hash --toml` と `/mcc2s whitelist add` が共用する。
     */
    public static String snippet(EntryKind kind, String id, String version, String sha256, String note) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(oneLine(note)).append('\n');
        sb.append("[[").append(section(kind)).append(".allow]]\n");
        if (id != null && !id.isEmpty()) {
            sb.append("id = ").append(quote(id)).append('\n');
        }
        if (version != null && !version.isEmpty()) {
            sb.append("version = ").append(quote(version)).append('\n');
        }
        sb.append("sha256 = [").append(quote(sha256)).append("]\n");
        sb.append("note = ").append(quote(note)).append('\n');
        return sb.toString();
    }

    public static String section(EntryKind kind) {
        switch (kind) {
            case MOD:
                return "mods";
            case LIBRARY:
                return "libraries";
            case RESOURCE_PACK:
                return "resource_packs";
            case SHADER_PACK:
                return "shader_packs";
            case AGENT:
                return "agents";
            case OTHER_CODE:
                return "other_code";
            default:
                throw new IllegalArgumentException("no allow list for " + kind);
        }
    }

    private static boolean alreadyAllowed(PolicyConfig cfg, EntryKind kind, String sha) {
        for (AllowEntry a : cfg.kindPolicy(kind).allow()) {
            if (a.sha256().contains(sha)) {
                return true;
            }
        }
        return false;
    }

    /** TOML の基本文字列。バックスラッシュ・引用符・制御文字をエスケープする。 */
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
                    if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || c == ' ' || c == ' ') {
                        sb.append(String.format("\\u%04X", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    /** コメント行に入れる文字列から改行・制御文字を除く。 */
    private static String oneLine(String s) {
        return Sanitize.text(s, 100).replace('\n', ' ');
    }

    private static void writeAtomic(Path target, String content) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
