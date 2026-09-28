// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.AllowEntry;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfigException;
import io.github.katyusha8138.mcc2s.core.policy.TomlPolicyLoader;
import io.github.katyusha8138.mcc2s.core.policy.Violation;
import io.github.katyusha8138.mcc2s.core.policy.ViolationCode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolicyEditorTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-28T00:00:00Z"), ZoneOffset.UTC);
    @TempDir Path tmp;
    Path policy;

    @BeforeEach
    void setUp() throws Exception {
        policy = tmp.resolve("policy.toml");
        Files.writeString(policy, TomlPolicyLoader.defaultTemplate(), StandardCharsets.UTF_8);
    }

    private static Violation notAllowed(EntryKind kind, String id, String version, String sha) {
        return new Violation(ViolationCode.NOT_ALLOWED, kind, id, version, sha, "not in allow list");
    }

    private PolicyConfig reload() throws Exception {
        return TomlPolicyLoader.parse(Files.readString(policy));
    }

    @Test
    void approvedViolationsBecomeAllowEntriesAndAreThenAccepted() throws Exception {
        String sodium = Harness.sha("sodium");
        String pack = Harness.sha("pack");
        PolicyEditor.Result r = PolicyEditor.approve(
                policy,
                List.of(
                        notAllowed(EntryKind.MOD, "sodium", "0.6.0", sodium),
                        notAllowed(EntryKind.RESOURCE_PACK, "file/Faithful.zip", "", pack)),
                "added by /mcc2s whitelist add Alex",
                CLOCK);
        assertEquals(2, r.added().size());

        PolicyConfig cfg = reload();
        AllowEntry mod = cfg.kindPolicy(EntryKind.MOD).allow().get(0);
        assertEquals("sodium", mod.id());
        assertEquals("0.6.0", mod.version());
        assertTrue(mod.sha256().contains(sodium));
        assertTrue(cfg.kindPolicy(EntryKind.RESOURCE_PACK).allow().get(0).sha256().contains(pack));
        assertTrue(mod.note().contains("2026-09-28"));
    }

    @Test
    void existingContentIsPreservedByteForByte() throws Exception {
        String before = Files.readString(policy);
        PolicyEditor.approve(policy, List.of(notAllowed(EntryKind.MOD, "m", "1", Harness.sha("m"))), "note", CLOCK);
        assertTrue(Files.readString(policy).startsWith(before), "only appends; never rewrites the operator's comments or layout");
    }

    @Test
    void repeatedApprovalIsIdempotent() throws Exception {
        List<Violation> v = List.of(notAllowed(EntryKind.MOD, "m", "1", Harness.sha("m")));
        assertEquals(1, PolicyEditor.approve(policy, v, "n", CLOCK).added().size());
        PolicyEditor.Result again = PolicyEditor.approve(policy, v, "n", CLOCK);
        assertTrue(again.added().isEmpty());
        assertTrue(again.skipped().get(0).contains("already allowed"));
        assertEquals(1, reload().kindPolicy(EntryKind.MOD).allow().size());
    }

    @Test
    void unapprovableViolationsAreSkippedWithAReason() throws Exception {
        PolicyEditor.Result r = PolicyEditor.approve(
                policy,
                List.of(
                        new Violation(ViolationCode.SELF_UNOFFICIAL, EntryKind.SELF, "mcc2s", "", Harness.sha("x"), ""),
                        new Violation(ViolationCode.SCOPE_MISSING, null, "MODS", "", "", ""),
                        new Violation(ViolationCode.PROOF_INVALID, EntryKind.MOD, "liar", "", Harness.sha("l"), ""),
                        notAllowed(EntryKind.MOD, "broken", "", ModScanner.UNREADABLE_SHA)),
                "n",
                CLOCK);
        assertTrue(r.added().isEmpty());
        assertEquals(4, r.skipped().size());
        assertEquals(TomlPolicyLoader.defaultTemplate(), Files.readString(policy), "nothing is written when nothing is approvable");
    }

    @Test
    void hostileStringsCannotInjectSettings() throws Exception {
        // クライアントが名乗る id に、TOML を壊す/新しい設定を注入する文字列を入れても、値として保存されるだけ
        String evilId = "x\"\nmode = \"audit\"\n[[mods.allow]]\nsha256 = \"" + Harness.sha("all") + "\" \\ end";
        PolicyEditor.approve(policy, List.of(notAllowed(EntryKind.MOD, evilId, "1\"2", Harness.sha("evil"))), "n\nmode=\"audit\"", CLOCK);
        PolicyConfig cfg = reload();
        assertEquals(io.github.katyusha8138.mcc2s.core.policy.EnforcementMode.ENFORCE, cfg.mode());
        assertEquals(1, cfg.kindPolicy(EntryKind.MOD).allow().size());
        assertEquals(evilId, cfg.kindPolicy(EntryKind.MOD).allow().get(0).id());
    }

    @Test
    void incompatibleMatchModeLeavesTheFileUntouched() throws Exception {
        // id_version モードでバージョンの無い項目を許可しようとすると設定が壊れる → 何も書かない
        Files.writeString(policy, "[mods]\nmatch = \"id_version\"\n");
        String before = Files.readString(policy);
        assertThrows(PolicyConfigException.class, () -> PolicyEditor.approve(
                policy, List.of(notAllowed(EntryKind.MOD, "m", "", Harness.sha("m"))), "n", CLOCK));
        assertEquals(before, Files.readString(policy));
    }

    @Test
    void approveHashWorksForEveryKind() throws Exception {
        for (EntryKind kind : EntryKind.values()) {
            if (kind == EntryKind.SELF) {
                continue;
            }
            PolicyEditor.Result r = PolicyEditor.approveHash(policy, kind, Harness.sha("h-" + kind), "id-" + kind, "cli", CLOCK);
            assertEquals(1, r.added().size(), kind.toString());
        }
        PolicyConfig cfg = reload();
        assertFalse(cfg.kindPolicy(EntryKind.AGENT).allow().isEmpty());
        assertFalse(cfg.kindPolicy(EntryKind.SHADER_PACK).allow().isEmpty());
    }

    @Test
    void invalidExistingPolicyIsRefused() throws Exception {
        Files.writeString(policy, "mode = \"enforc\"\n");
        assertThrows(PolicyConfigException.class, () -> PolicyEditor.approve(
                policy, List.of(notAllowed(EntryKind.MOD, "m", "1", Harness.sha("m"))), "n", CLOCK));
    }

    @Test
    void quoteEscapesEverythingDangerous() {
        assertEquals("\"a\\\"b\\\\c\\u000Ad\"", PolicyEditor.quote("a\"b\\c\nd"));
    }
}
