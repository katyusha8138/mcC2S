// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfigException;
import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import java.io.IOException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * `/mcc2s` コマンドの中身(Minecraft 非依存)。ローダー側は引数を渡して、返ってきた行を表示するだけ。
 * ホワイトリストへの追加はサーバー運営者(OP)の明示的な操作でのみ行われ、追加した内容はすべて応答に出す。
 */
public final class AdminActions {
    public record Response(boolean ok, List<String> lines) {}

    private AdminActions() {}

    public static Response status(ServerRuntime rt) {
        ServerContext ctx = rt.context();
        PolicyConfig p = ctx.policy();
        List<String> lines = new ArrayList<>();
        lines.add("mcC2S " + rt.selfVersion() + " — mode=" + p.mode() + ", scopes=" + p.scopes());
        lines.add("baseline: " + ctx.baseline().size() + " server-side jar(s), trusted mcC2S builds: " + ctx.trustedSelfHashes().size());
        lines.add("proof rate: " + p.proofRatePercent() + "%, require_reference=" + p.requireReference()
                + ", handshake timeout: " + p.handshakeTimeoutSeconds() + "s");
        lines.add("reverify: " + (p.reverifyEnabled()
                ? "every " + p.reverifyMinSeconds() + "-" + p.reverifyMaxSeconds() + "s, on_change=" + p.reverifyOnChange()
                : "disabled"));
        lines.add("stats since start: " + ctx.stats().summary());
        lines.add("trust file: " + rt.trustFilePath());
        return new Response(true, lines);
    }

    public static Response reload(ServerRuntime rt) {
        ServerRuntime.ReloadResult r = rt.reload();
        return new Response(r.ok(), List.of(r.message()));
    }

    /** `/mcc2s whitelist add <player>`: そのプレイヤーの直近の違反のうち、許可できるものを policy.toml に追記して再読込する。 */
    public static Response whitelistAdd(ServerRuntime rt, String player, String source, Clock clock) {
        Optional<ViolationReport> last = rt.lastViolations().get(player);
        if (last.isEmpty()) {
            return new Response(false, List.of("no recent violation is recorded for '" + Sanitize.text(player, 32)
                    + "' (they must have been denied or logged in audit mode since the server started)"));
        }
        return approve(rt, last.get().violations(), "added by " + Sanitize.text(source, 32) + " for " + Sanitize.text(player, 32), clock);
    }

    /** `/mcc2s whitelist addhash <kind> <sha256> [id]`。 */
    public static Response whitelistAddHash(ServerRuntime rt, String kindName, String sha256, String id, String source, Clock clock) {
        EntryKind kind;
        try {
            kind = EntryKindNames.parse(kindName);
        } catch (IllegalArgumentException e) {
            return new Response(false, List.of(e.getMessage()));
        }
        String sha = sha256.toLowerCase(Locale.ROOT);
        if (!Digests.isSha256Hex(sha)) {
            return new Response(false, List.of("sha256 must be 64 hex characters"));
        }
        return approve(rt, List.of(new io.github.katyusha8138.mcc2s.core.policy.Violation(
                io.github.katyusha8138.mcc2s.core.policy.ViolationCode.NOT_ALLOWED, kind, id == null ? "" : id, "", sha, "")),
                "added by " + Sanitize.text(source, 32), clock);
    }

    private static Response approve(ServerRuntime rt, List<io.github.katyusha8138.mcc2s.core.policy.Violation> violations, String note, Clock clock) {
        List<String> lines = new ArrayList<>();
        try {
            PolicyEditor.Result r = PolicyEditor.approve(rt.policyPath(), violations, note, clock);
            for (PolicyEditor.Added a : r.added()) {
                lines.add("allowed " + a.kind() + " " + (a.id().isEmpty() ? "(no id)" : a.id()) + " sha256=" + a.sha256());
            }
            for (String s : r.skipped()) {
                lines.add("skipped " + s);
            }
            if (r.added().isEmpty()) {
                lines.add("nothing was added");
                return new Response(false, lines);
            }
            ServerRuntime.ReloadResult reload = rt.reload();
            lines.add(reload.message());
            return new Response(reload.ok(), lines);
        } catch (PolicyConfigException e) {
            lines.add("policy.toml was NOT changed: " + e.getMessage());
            return new Response(false, lines);
        } catch (IOException e) {
            lines.add("could not update policy.toml: " + e.getMessage());
            return new Response(false, lines);
        }
    }
}
