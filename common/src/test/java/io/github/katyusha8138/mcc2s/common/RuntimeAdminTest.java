// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.EnforcementMode;
import io.github.katyusha8138.mcc2s.core.policy.Violation;
import io.github.katyusha8138.mcc2s.core.policy.ViolationCode;
import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RuntimeAdminTest {
    @TempDir Path tmp;
    private final Log log = Log.stdout();

    private ViolationReport report(String player, String id) {
        return new ViolationReport(
                Instant.EPOCH,
                player,
                UUID.randomUUID(),
                "127.0.0.1",
                new byte[8],
                ServerVerdict.Status.DENIED,
                List.of(new Violation(ViolationCode.NOT_ALLOWED, EntryKind.MOD, id, "1", Harness.sha(id), "")));
    }

    // ---- LastViolations ----

    @Test
    void lastViolationsKeepsTheMostRecentReportPerPlayerCaseInsensitively() {
        LastViolations lv = new LastViolations();
        lv.record(report("Steve", "first"));
        lv.record(report("steve", "second"));
        assertEquals(1, lv.size());
        assertEquals("second", lv.get("STEVE").orElseThrow().violations().get(0).id());
        assertTrue(lv.get("nobody").isEmpty());
    }

    @Test
    void lastViolationsIsBoundedSoNameSpamCannotExhaustMemory() {
        LastViolations lv = new LastViolations();
        for (int i = 0; i < 1000; i++) {
            lv.record(report("bot" + i, "m"));
        }
        assertEquals(256, lv.size());
        assertTrue(lv.get("bot999").isPresent());
        assertTrue(lv.get("bot0").isEmpty());
    }

    // ---- ServerStats ----

    @Test
    void statsCountAndSummarize() {
        ServerStats s = new ServerStats();
        s.inc(ServerStats.Counter.VERIFIED);
        s.inc(ServerStats.Counter.VERIFIED);
        s.inc(ServerStats.Counter.DENIED);
        assertEquals(2, s.get(ServerStats.Counter.VERIFIED));
        assertTrue(s.summary().contains("verified=2") && s.summary().contains("denied=1") && s.summary().contains("timeout=0"));
    }

    @Test
    void verificationsUpdateTheStats() throws Exception {
        Harness h = new Harness(tmp);
        h.serverOwn.add(h.seed(EntryKind.MOD, "create", "6.0", h.file(h.serverDir, "create.jar", "create")));

        Harness.Outcome ok = h.connect("Ok", () -> List.of(
                h.seed(EntryKind.MOD, "create", "6.0", h.file(h.clientDir, "create.jar", "create")), h.selfSeed(h.clientDir)));
        assertTrue(ok.allowed);
        assertEquals(1, h.lastContext.stats().get(ServerStats.Counter.VERIFIED));

        Harness.Outcome bad = h.connect("Bad", () -> List.of(
                h.seed(EntryKind.MOD, "wurst", "1", h.file(h.clientDir, "wurst.jar", "cheat")), h.selfSeed(h.clientDir)));
        assertTrue(bad.kicked());
        assertEquals(1, h.lastContext.stats().get(ServerStats.Counter.DENIED));
        assertEquals(0, h.lastContext.stats().get(ServerStats.Counter.REVERIFY_KICKED), "a join-time denial is not a re-verification kick");
    }

    @Test
    void recheckModeCountsSeparatelyAndUsesTheSameStrictness() throws Exception {
        Harness h = new Harness(tmp);
        h.serverOwn.add(h.seed(EntryKind.MOD, "create", "6.0", h.file(h.serverDir, "create.jar", "create")));
        h.recheck = true;

        Harness.Outcome ok = h.connect("Ok", () -> List.of(
                h.seed(EntryKind.MOD, "create", "6.0", h.file(h.clientDir, "create.jar", "create")), h.selfSeed(h.clientDir)));
        assertTrue(ok.allowed);
        assertEquals(1, h.lastContext.stats().get(ServerStats.Counter.REVERIFIED));
        assertEquals(0, h.lastContext.stats().get(ServerStats.Counter.VERIFIED));

        // ログイン後に導入された隠し jar: 再検証でも参加時と同じ厳格さで拒否される
        Harness.Outcome bad = h.connect("Late", () -> List.of(
                h.seed(EntryKind.MOD, "create", "6.0", h.file(h.clientDir, "create.jar", "create")),
                h.seed(EntryKind.LIBRARY, "late-cheat.jar", "", h.file(h.clientDir, "late.jar", "cheat")),
                h.selfSeed(h.clientDir)));
        assertTrue(bad.kicked());
        assertEquals(1, h.lastContext.stats().get(ServerStats.Counter.REVERIFY_KICKED));
        assertTrue(h.logLines.stream().anyMatch(l -> l.contains("Ok re-verified")));
    }

    // ---- ServerRuntime.reload ----

    private ServerRuntime start() throws Exception {
        Path game = Files.createDirectories(tmp.resolve("game"));
        Path mods = Files.createDirectories(game.resolve("mods"));
        Path self = mods.resolve("mcc2s.jar");
        Files.writeString(self, "self bytes");
        var inputs = new ServerRuntime.Inputs(
                game.resolve("config/mcc2s"), mods, game.resolve("logs"), List.of(), Set.of("minecraft", "neoforge"), self, "0.1.0", "t", log);
        return ServerRuntime.start(inputs, Harness.RND);
    }

    @Test
    void reloadPicksUpPolicyChangesAndKeepsTheOldOnesOnErrors() throws Exception {
        try (ServerRuntime rt = start()) {
            assertEquals(EnforcementMode.ENFORCE, rt.context().policy().mode());

            String text = Files.readString(rt.policyPath());
            Files.writeString(rt.policyPath(), text.replace("mode = \"enforce\"", "mode = \"audit\""));
            ServerRuntime.ReloadResult ok = rt.reload();
            assertTrue(ok.ok(), ok.message());
            assertEquals(EnforcementMode.AUDIT, rt.context().policy().mode());

            // 壊れた設定: 失敗を返し、直前の設定(audit)のまま動き続ける
            Files.writeString(rt.policyPath(), "mode = \"enforc\"\n");
            ServerRuntime.ReloadResult bad = rt.reload();
            assertFalse(bad.ok());
            assertTrue(bad.message().contains("keeping the previous settings"));
            assertEquals(EnforcementMode.AUDIT, rt.context().policy().mode());
        }
    }

    @Test
    void reloadSharesStatsAndTheViolationSinkWithTheOldContext() throws Exception {
        try (ServerRuntime rt = start()) {
            ServerStats before = rt.context().stats();
            rt.reload();
            assertTrue(before == rt.context().stats(), "counters must survive a reload");
            assertTrue(rt.context().worker() != null);
        }
    }

    @Test
    void violationsReportedThroughTheRuntimeAreRemembered() throws Exception {
        try (ServerRuntime rt = start()) {
            rt.context().sink().report(report("Cheater", "wurst"));
            assertEquals("wurst", rt.lastViolations().get("cheater").orElseThrow().violations().get(0).id());
            assertTrue(Files.readString(tmp.resolve("game/logs/violations.jsonl")).contains("wurst"));
        }
    }
}
