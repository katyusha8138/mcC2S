// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.policy.EnforcementMode;
import io.github.katyusha8138.mcc2s.core.policy.PolicyEvaluator;
import io.github.katyusha8138.mcc2s.core.policy.ReferenceResolver;
import io.github.katyusha8138.mcc2s.core.policy.Violation;
import io.github.katyusha8138.mcc2s.core.policy.ViolationCode;
import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AdminActionsTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-28T00:00:00Z"), ZoneOffset.UTC);
    @TempDir Path tmp;

    private ServerRuntime start() throws Exception {
        Path game = Files.createDirectories(tmp.resolve("game"));
        Path mods = Files.createDirectories(game.resolve("mods"));
        Path self = mods.resolve("mcc2s.jar");
        Files.writeString(self, "self bytes");
        var inputs = new ServerRuntime.Inputs(
                game.resolve("config/mcc2s"), mods, game.resolve("logs"), List.of(), Set.of("minecraft", "neoforge"), self, "0.1.0", "t", Log.stdout());
        return ServerRuntime.start(inputs, Harness.RND);
    }

    private static void denied(ServerRuntime rt, String player, Violation... v) {
        rt.context().sink().report(new ViolationReport(
                Instant.EPOCH, player, UUID.randomUUID(), "127.0.0.1", new byte[8], ServerVerdict.Status.DENIED, List.of(v)));
    }

    private static Violation notAllowed(EntryKind kind, String id, String sha) {
        return new Violation(ViolationCode.NOT_ALLOWED, kind, id, "1.0", sha, "");
    }

    @Test
    void statusSummarizesTheRuntime() throws Exception {
        try (ServerRuntime rt = start()) {
            AdminActions.Response r = AdminActions.status(rt);
            assertTrue(r.ok());
            String all = String.join("\n", r.lines());
            assertTrue(all.contains("mcC2S 0.1.0") && all.contains("mode=ENFORCE"));
            assertTrue(all.contains("baseline: 1") && all.contains("trusted mcC2S builds: 1"));
            assertTrue(all.contains("every 300-900s") && all.contains("on_change=true"));
            assertTrue(all.contains("verified=0") && all.contains(".mc2strust"));
        }
    }

    @Test
    void reloadReportsSuccessAndFailure() throws Exception {
        try (ServerRuntime rt = start()) {
            assertTrue(AdminActions.reload(rt).ok());
            Files.writeString(rt.policyPath(), "mode = \"enforc\"\n");
            AdminActions.Response bad = AdminActions.reload(rt);
            assertFalse(bad.ok());
            assertTrue(bad.lines().get(0).contains("keeping the previous settings"));
        }
    }

    @Test
    void whitelistAddApprovesTheLastViolationsAndAppliesThemImmediately() throws Exception {
        try (ServerRuntime rt = start()) {
            String sodium = Harness.sha("sodium");
            denied(rt, "Alex", notAllowed(EntryKind.MOD, "sodium", sodium), notAllowed(EntryKind.LIBRARY, "lib.jar", Harness.sha("lib")));

            AdminActions.Response r = AdminActions.whitelistAdd(rt, "alex", "Console", CLOCK);
            assertTrue(r.ok(), r.lines().toString());
            String all = String.join("\n", r.lines());
            assertTrue(all.contains("allowed MOD sodium sha256=" + sodium));
            assertTrue(all.contains("allowed LIBRARY lib.jar"));
            assertTrue(all.contains("policy reloaded"));

            // 再読込後のポリシーで、同じ構成のクライアントが通る
            Manifest m = new Manifest("1", "neoforge", "21", "0.1.0", EnumSet.allOf(Scope.class), List.of(
                    new Entry(EntryKind.SELF, "mcc2s", "0.1.0", rt.context().trustedSelfHashes().iterator().next()),
                    new Entry(EntryKind.MOD, "sodium", "1.0", sodium)));
            assertTrue(PolicyEvaluator.evaluate(rt.context().policy(), m, List.of(), rt.context().trustedSelfHashes(), null, ReferenceResolver.none()).clean());
            assertEquals(EnforcementMode.ENFORCE, rt.context().policy().mode());
        }
    }

    @Test
    void whitelistAddRefusesWhenThereIsNothingToApprove() throws Exception {
        try (ServerRuntime rt = start()) {
            AdminActions.Response none = AdminActions.whitelistAdd(rt, "ghost", "Console", CLOCK);
            assertFalse(none.ok());
            assertTrue(none.lines().get(0).contains("no recent violation"));

            // 自己改造(SELF_UNOFFICIAL)や範囲不足は許可リストでは直せない
            denied(rt, "Hacker", new Violation(ViolationCode.SELF_UNOFFICIAL, EntryKind.SELF, "mcc2s", "", Harness.sha("x"), ""));
            String before = Files.readString(rt.policyPath());
            AdminActions.Response r = AdminActions.whitelistAdd(rt, "Hacker", "Console", CLOCK);
            assertFalse(r.ok());
            assertTrue(String.join("\n", r.lines()).contains("nothing was added"));
            assertEquals(before, Files.readString(rt.policyPath()));
        }
    }

    @Test
    void whitelistAddHashValidatesItsArguments() throws Exception {
        try (ServerRuntime rt = start()) {
            assertFalse(AdminActions.whitelistAddHash(rt, "banana", Harness.sha("x"), "x", "c", CLOCK).ok());
            assertFalse(AdminActions.whitelistAddHash(rt, "mod", "nothex", "x", "c", CLOCK).ok());

            AdminActions.Response ok = AdminActions.whitelistAddHash(rt, "resource-pack", Harness.sha("p").toUpperCase(), "file/x.zip", "c", CLOCK);
            assertTrue(ok.ok(), ok.lines().toString());
            assertTrue(rt.context().policy().kindPolicy(EntryKind.RESOURCE_PACK).allow().get(0).sha256().contains(Harness.sha("p")));

            // 同じハッシュを重ねて追加しても増えない
            AdminActions.Response again = AdminActions.whitelistAddHash(rt, "resource-pack", Harness.sha("p"), "file/x.zip", "c", CLOCK);
            assertFalse(again.ok());
            assertEquals(1, rt.context().policy().kindPolicy(EntryKind.RESOURCE_PACK).allow().size());
        }
    }

    @Test
    void entryKindNamesRoundTrip() {
        for (String n : EntryKindNames.NAMES) {
            assertEquals(EntryKindNames.NAMES.contains(n), true);
            EntryKindNames.parse(n.toUpperCase());
        }
        assertThrows(IllegalArgumentException.class, () -> EntryKindNames.parse("self"));
    }
}
