// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.ProofContext;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class PolicyEvaluatorTest {
    private static final String OFFICIAL = Fixtures.sha("mcc2s-official");
    private static final Set<String> TRUSTED_SELF = Set.of(OFFICIAL);
    private static final Set<Scope> ALL = Fixtures.ALL_SCOPES;

    private static Entry self() {
        return new Entry(EntryKind.SELF, "mcc2s", "0.1.0", OFFICIAL);
    }

    private static Entry mod(String id, String version, String seed) {
        return new Entry(EntryKind.MOD, id, version, Fixtures.sha(seed));
    }

    private static Evaluation eval(PolicyConfig cfg, List<Entry> baseline, Entry... entries) {
        return PolicyEvaluator.evaluate(
                cfg, Fixtures.manifest(ALL, entries), baseline, TRUSTED_SELF, null, ReferenceResolver.none());
    }

    private static Set<ViolationCode> codes(Evaluation e) {
        return e.violations().stream().map(Violation::code).collect(Collectors.toSet());
    }

    private static AllowEntry allowHash(String id, String seed) {
        return new AllowEntry(id, null, Set.of(Fixtures.sha(seed)), "");
    }

    // ---- 基本 ----

    @Test
    void serverModsAndWhitelistedModsAreAllowed() {
        PolicyConfig cfg = PolicyConfig.builder()
                .kind(EntryKind.MOD, new KindPolicy(MatchMode.HASH, true, List.of(allowHash("sodium", "sodium-jar"))))
                .build();
        List<Entry> baseline = List.of(mod("create", "6.0", "create-jar"));
        Evaluation e = eval(cfg, baseline, self(), mod("create", "6.0", "create-jar"), mod("sodium", "0.6", "sodium-jar"));
        assertTrue(e.clean(), e.violations().toString());
    }

    @Test
    void unknownModIsRejected() {
        Evaluation e = eval(PolicyConfig.defaults(), List.of(), self(), mod("wurst", "7.0", "wurst-jar"));
        assertEquals(Set.of(ViolationCode.NOT_ALLOWED), codes(e));
        assertFalse(e.permits(EnforcementMode.ENFORCE));
        assertTrue(e.permits(EnforcementMode.AUDIT));
    }

    @Test
    void sameIdDifferentHashIsHashMismatch() {
        // サーバーと同じ ID・バージョンを名乗る改造 jar
        List<Entry> baseline = List.of(mod("create", "6.0", "create-jar"));
        Evaluation e = eval(PolicyConfig.defaults(), baseline, self(), mod("create", "6.0", "create-jar-hacked"));
        assertEquals(Set.of(ViolationCode.HASH_MISMATCH), codes(e));
    }

    @Test
    void idVersionModeToleratesDifferentBuildsOfSameVersion() {
        PolicyConfig cfg = PolicyConfig.builder()
                .kind(EntryKind.MOD, new KindPolicy(MatchMode.ID_VERSION, true, List.of()))
                .build();
        List<Entry> baseline = List.of(mod("create", "6.0", "create-jar"));
        assertTrue(eval(cfg, baseline, self(), mod("create", "6.0", "other-build")).clean());
        assertFalse(eval(cfg, baseline, self(), mod("create", "6.1", "other-build")).clean());
    }

    @Test
    void idModeIgnoresVersion() {
        PolicyConfig cfg = PolicyConfig.builder()
                .kind(EntryKind.MOD, new KindPolicy(MatchMode.ID, true, List.of(new AllowEntry("sodium", null, null, ""))))
                .build();
        assertTrue(eval(cfg, List.of(), self(), mod("sodium", "9.9", "anything")).clean());
        assertFalse(eval(cfg, List.of(), self(), mod("other", "1", "x")).clean());
    }

    @Test
    void baselineCanBeDisabled() {
        PolicyConfig cfg = PolicyConfig.builder()
                .kind(EntryKind.MOD, new KindPolicy(MatchMode.HASH, false, List.of()))
                .build();
        Evaluation e = eval(cfg, List.of(mod("create", "6.0", "create-jar")), self(), mod("create", "6.0", "create-jar"));
        assertEquals(Set.of(ViolationCode.NOT_ALLOWED), codes(e));
    }

    @Test
    void baselineIsPerKind() {
        // サーバーの Mod ハッシュを、ライブラリとして名乗っても通らない
        List<Entry> baseline = List.of(mod("create", "6.0", "create-jar"));
        Entry asLibrary = new Entry(EntryKind.LIBRARY, "create", "6.0", Fixtures.sha("create-jar"));
        assertEquals(Set.of(ViolationCode.NOT_ALLOWED), codes(eval(PolicyConfig.defaults(), baseline, self(), asLibrary)));
    }

    @Test
    void hiddenLibraryJarsAreCheckedLikeMods() {
        Entry hidden = new Entry(EntryKind.LIBRARY, "innocent-lib.jar", "", Fixtures.sha("cheat-loader"));
        assertEquals(Set.of(ViolationCode.NOT_ALLOWED), codes(eval(PolicyConfig.defaults(), List.of(), self(), hidden)));
    }

    @Test
    void resourcePacksShadersAndAgents() {
        PolicyConfig cfg = PolicyConfig.builder()
                .kind(EntryKind.RESOURCE_PACK, new KindPolicy(MatchMode.HASH, true, List.of(allowHash("file/ok.zip", "ok-pack"))))
                .build();
        Entry okPack = new Entry(EntryKind.RESOURCE_PACK, "file/ok.zip", "", Fixtures.sha("ok-pack"));
        Entry xray = new Entry(EntryKind.RESOURCE_PACK, "file/xray.zip", "", Fixtures.sha("xray"));
        Entry shader = new Entry(EntryKind.SHADER_PACK, "xray-shader.zip", "", Fixtures.sha("xs"));
        Entry agent = new Entry(EntryKind.AGENT, "cheat-agent.jar", "", Fixtures.sha("agent"));
        Entry other = new Entry(EntryKind.OTHER_CODE, "unknown.jar", "", Fixtures.sha("oc"));

        assertTrue(eval(cfg, List.of(), self(), okPack).clean());
        Evaluation e = eval(cfg, List.of(), self(), okPack, xray, shader, agent, other);
        assertEquals(4, e.violations().size());
        assertEquals(Set.of(ViolationCode.NOT_ALLOWED), codes(e));
    }

    @Test
    void scopesNotRequestedAreIgnoredWithNotice() {
        PolicyConfig cfg = PolicyConfig.builder().scopes(EnumSet.of(Scope.MODS)).build();
        Entry shader = new Entry(EntryKind.SHADER_PACK, "s.zip", "", Fixtures.sha("s"));
        Manifest m = Fixtures.manifest(EnumSet.of(Scope.MODS), self(), shader);
        Evaluation e = PolicyEvaluator.evaluate(cfg, m, List.of(), TRUSTED_SELF, null, ReferenceResolver.none());
        assertTrue(e.clean());
        assertEquals(1, e.notices().size());
    }

    // ---- 範囲・SELF ----

    @Test
    void missingScopeIsAViolation() {
        Manifest m = Fixtures.manifest(EnumSet.of(Scope.MODS), self()); // シェーダー/エージェント等を「未報告」
        Evaluation e = PolicyEvaluator.evaluate(
                PolicyConfig.defaults(), m, List.of(), TRUSTED_SELF, null, ReferenceResolver.none());
        assertEquals(Set.of(ViolationCode.SCOPE_MISSING), codes(e));
        assertEquals(3, e.violations().size());
    }

    @Test
    void selfMustBePresentOfficialAndUnique() {
        assertEquals(Set.of(ViolationCode.SELF_MISSING), codes(eval(PolicyConfig.defaults(), List.of())));
        Entry modified = new Entry(EntryKind.SELF, "mcc2s", "0.1.0", Fixtures.sha("patched-build"));
        assertEquals(Set.of(ViolationCode.SELF_UNOFFICIAL), codes(eval(PolicyConfig.defaults(), List.of(), modified)));
        assertEquals(Set.of(ViolationCode.DUPLICATE_SELF), codes(eval(PolicyConfig.defaults(), List.of(), self(), self())));
        // 公式 + 改造の 2 つを並べても通らない
        Set<ViolationCode> both = codes(eval(PolicyConfig.defaults(), List.of(), self(), modified));
        assertTrue(both.contains(ViolationCode.SELF_UNOFFICIAL) && both.contains(ViolationCode.DUPLICATE_SELF));
    }

    // ---- 測定証明 ----

    private static Optional<java.io.InputStream> stream(byte[] b) {
        return Optional.of(new ByteArrayInputStream(b));
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String shaOf(byte[] b) {
        return Digests.hex(Digests.sha256(b));
    }

    /** サーバーが持つ参照ファイル(ハッシュ → 内容)。 */
    private static ReferenceResolver refs(Map<String, byte[]> files) {
        return (kind, sha) -> files.containsKey(sha) ? stream(files.get(sha)) : Optional.empty();
    }

    private static final class Ctx {
        final Fixtures fx = Fixtures.create();
        final byte[] selfJar = bytes("official mcc2s jar");
        final byte[] createJar = bytes("create jar");
        final byte[] sodiumJar = bytes("sodium jar (client only)");
    }

    private Evaluation runProofScenario(
            Ctx c, int rate, boolean requireReference, boolean sodiumHasReference, boolean tamperCreateProof, boolean omitProofs)
            throws Exception {
        String selfSha = shaOf(c.selfJar);
        String createSha = shaOf(c.createJar);
        String sodiumSha = shaOf(c.sodiumJar);

        Fixtures.Session s = c.fx.run(ALL, rate, client -> {
            try {
                ProofContext p = client.proofs();
                List<Entry> out = new ArrayList<>();
                out.add(withProof(p, EntryKind.SELF, "mcc2s", selfSha, c.selfJar, false, omitProofs));
                out.add(withProof(p, EntryKind.MOD, "create", createSha, tamperCreateProof ? bytes("not the real jar") : c.createJar, false, omitProofs));
                out.add(withProof(p, EntryKind.MOD, "sodium", sodiumSha, c.sodiumJar, false, omitProofs));
                return out;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });

        Map<String, byte[]> files = new java.util.HashMap<>();
        files.put(selfSha, c.selfJar);
        files.put(createSha, c.createJar);
        if (sodiumHasReference) {
            files.put(sodiumSha, c.sodiumJar);
        }
        PolicyConfig cfg = PolicyConfig.builder()
                .proofRatePercent(rate)
                .requireReference(requireReference)
                .kind(EntryKind.MOD, new KindPolicy(MatchMode.HASH, true, List.of(new AllowEntry("sodium", null, Set.of(sodiumSha), ""))))
                .build();
        List<Entry> baseline = List.of(new Entry(EntryKind.MOD, "create", "1", createSha));
        return PolicyEvaluator.evaluate(
                cfg, s.opened.manifest(), baseline, Set.of(selfSha), s.opened.proofs(), refs(files));
    }

    private static Entry withProof(ProofContext p, EntryKind kind, String id, String sha, byte[] actualBytes, boolean unused, boolean omit)
            throws IOException {
        byte[] proof = omit ? null : p.prove(kind, sha, new ByteArrayInputStream(actualBytes));
        return new Entry(kind, id, "1", sha, proof);
    }

    @Test
    void validProofsPass() throws Exception {
        Evaluation e = runProofScenario(new Ctx(), 100, false, true, false, false);
        assertTrue(e.clean(), e.violations().toString());
        assertTrue(e.notices().isEmpty());
    }

    @Test
    void claimingAHashWithoutHoldingTheFileIsCaught() throws Exception {
        // ハッシュ一覧だけを偽装し、実際のファイルを持たないクライアント(サーバー側 Mod と同じハッシュを名乗る)
        Evaluation e = runProofScenario(new Ctx(), 100, false, true, true, false);
        assertEquals(Set.of(ViolationCode.PROOF_INVALID), codes(e));
        assertEquals("create", e.violations().get(0).id());
    }

    @Test
    void missingRequiredProofIsAViolationWhenReferenceExists() throws Exception {
        Evaluation e = runProofScenario(new Ctx(), 100, false, true, false, true);
        assertEquals(Set.of(ViolationCode.PROOF_MISSING), codes(e));
        assertEquals(3, e.violations().size());
    }

    @Test
    void unverifiableProofBecomesNoticeUnlessReferenceRequired() throws Exception {
        Evaluation lenient = runProofScenario(new Ctx(), 100, false, false, false, false);
        assertTrue(lenient.clean());
        assertEquals(1, lenient.notices().size()); // sodium は参照ファイルが無く、証明を検証できない

        Evaluation strict = runProofScenario(new Ctx(), 100, true, false, false, false);
        assertEquals(Set.of(ViolationCode.PROOF_UNVERIFIABLE), codes(strict));
    }

    @Test
    void selfProofIsAlwaysCheckedEvenAtZeroRate() throws Exception {
        Ctx c = new Ctx();
        // rate 0 でも SELF は必須: 証明を省くと PROOF_MISSING
        Evaluation e = runProofScenario(c, 0, false, true, false, true);
        assertEquals(Set.of(ViolationCode.PROOF_MISSING), codes(e));
        assertEquals(1, e.violations().size());
        assertEquals(EntryKind.SELF, e.violations().get(0).kind());
    }

    @Test
    void nullProofContextSkipsProofChecking() {
        Evaluation e = eval(PolicyConfig.defaults(), Collections.emptyList(), self());
        assertTrue(e.clean());
    }
}
