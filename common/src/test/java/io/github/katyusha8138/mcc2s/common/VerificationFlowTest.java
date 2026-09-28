// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.handshake.Fragmenter;
import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.handshake.TrustStore;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.policy.AllowEntry;
import io.github.katyusha8138.mcc2s.core.policy.EnforcementMode;
import io.github.katyusha8138.mcc2s.core.policy.KindPolicy;
import io.github.katyusha8138.mcc2s.core.policy.MatchMode;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VerificationFlowTest {
    @TempDir Path tmp;
    Harness h;
    EntrySeed serverCreate;

    @BeforeEach
    void setUp() throws Exception {
        h = new Harness(tmp);
        serverCreate = h.seed(EntryKind.MOD, "create", "6.0", h.file(h.serverDir, "create.jar", "create bytes"));
        h.serverOwn.add(serverCreate);
    }

    /** 正規クライアント: サーバーと同じ Mod + 同じ mcC2S を持つ。 */
    private List<EntrySeed> legitClient() throws Exception {
        List<EntrySeed> seeds = new ArrayList<>();
        seeds.add(h.seed(EntryKind.MOD, "create", "6.0", h.file(h.clientDir, "create.jar", "create bytes")));
        seeds.add(h.selfSeed(h.clientDir));
        return seeds;
    }

    // ---- 許可 ----

    @Test
    void legitClientIsAllowedAndSeesAVerdict() throws Exception {
        h.policy = PolicyConfig.builder().proofRatePercent(100).build();
        Harness.Outcome o = h.connect("Steve", this::legitClient);
        assertTrue(o.allowed, () -> o.kicks + " " + o.aborts + " " + h.logLines);
        assertFalse(o.kicked());
        assertTrue(o.aborts.isEmpty());
        assertTrue(h.reports.isEmpty());
        assertEquals(ServerVerdict.Status.ALLOWED, o.client.verdict().orElseThrow().status());
    }

    @Test
    void whitelistedClientOnlyModIsAllowed() throws Exception {
        String sodiumSha = h.cache.sha256(h.file(h.clientDir, "sodium.jar", "sodium bytes"));
        h.policy = PolicyConfig.builder()
                .kind(EntryKind.MOD, new KindPolicy(MatchMode.HASH, true, List.of(new AllowEntry("sodium", null, Set.of(sodiumSha), ""))))
                .build();
        Harness.Outcome o = h.connect("Alex", () -> {
            List<EntrySeed> s = legitClient();
            s.add(h.seed(EntryKind.MOD, "sodium", "0.6", h.clientDir.resolve("sodium.jar")));
            return s;
        });
        assertTrue(o.allowed, () -> o.kicks.toString());
    }

    // ---- 拒否 ----

    @Test
    void unknownModIsKickedAndReported() throws Exception {
        Harness.Outcome o = h.connect("Cheater", () -> {
            List<EntrySeed> s = legitClient();
            s.add(h.seed(EntryKind.MOD, "wurst", "7.0", h.file(h.clientDir, "wurst.jar", "cheat bytes")));
            return s;
        });
        assertFalse(o.allowed);
        assertEquals(1, o.kicks.size());
        assertEquals(1, h.reports.size());
        assertTrue(o.kicks.get(0).contains(h.reports.get(0).refCode()), "player sees the same ref code as the log");
        assertFalse(o.kicks.get(0).contains("wurst"), "details are hidden from the player by default");
        String jsonLine = h.reports.get(0).toJsonLine();
        assertTrue(jsonLine.contains("\"NOT_ALLOWED\"") && jsonLine.contains("wurst") && jsonLine.contains("Cheater"));
        assertTrue(h.logLines.stream().anyMatch(l -> l.contains("DENIED") && l.contains("Cheater")));
        // JSON Lines ファイルにも 1 行追記される
        List<String> lines = java.nio.file.Files.readAllLines(tmp.resolve("logs/violations.jsonl"));
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).contains(h.reports.get(0).refCode()));
    }

    @Test
    void detailsCanBeShownToThePlayer() throws Exception {
        h.policy = PolicyConfig.builder().showDetailsToPlayer(true).build();
        Harness.Outcome o = h.connect("Cheater", () -> {
            List<EntrySeed> s = legitClient();
            s.add(h.seed(EntryKind.MOD, "wurst", "7.0", h.file(h.clientDir, "wurst.jar", "cheat bytes")));
            return s;
        });
        assertTrue(o.kicks.get(0).contains("wurst"));
    }

    @Test
    void hiddenLibraryJarAndUnauthorizedAgentAreCaught() throws Exception {
        Harness.Outcome o = h.connect("Sneaky", () -> {
            List<EntrySeed> s = legitClient();
            s.add(h.seed(EntryKind.LIBRARY, "innocent-lib.jar", "", h.file(h.clientDir, "lib.jar", "loader bytes")));
            s.add(h.seed(EntryKind.AGENT, "inject.jar", "", h.file(h.clientDir, "agent.jar", "agent bytes")));
            return s;
        });
        assertTrue(o.kicked());
        String json = h.reports.get(0).toJsonLine();
        assertTrue(json.contains("\"kind\":\"LIBRARY\"") && json.contains("innocent-lib.jar"));
        assertTrue(json.contains("\"kind\":\"AGENT\"") && json.contains("inject.jar"));
        // ヘッダ 1 行 + 違反 2 行
        assertEquals(3, h.reports.get(0).consoleLines().size());
    }

    @Test
    void modifiedMcC2SBuildIsRejected() throws Exception {
        Harness.Outcome o = h.connect("Hacker", () -> {
            List<EntrySeed> s = new ArrayList<>();
            s.add(h.seed(EntryKind.MOD, "create", "6.0", h.file(h.clientDir, "create.jar", "create bytes")));
            s.add(h.seed(EntryKind.SELF, "mcc2s", "0.1.0", h.file(h.clientDir, "mcc2s.jar", "PATCHED mcC2S build")));
            return s;
        });
        assertTrue(o.kicked());
        assertTrue(h.reports.get(0).toJsonLine().contains("SELF_UNOFFICIAL"));
    }

    @Test
    void claimingTheServersHashWithoutHoldingTheFileIsRejected() throws Exception {
        // 一覧だけ偽装し、実際のファイルは別物(測定証明でバレる)
        h.policy = PolicyConfig.builder().proofRatePercent(100).build();
        Harness.Outcome o = h.connect("Liar", () -> {
            List<EntrySeed> s = new ArrayList<>();
            EntrySeed fake = new EntrySeed(
                    EntryKind.MOD, "create", "6.0", serverCreate.sha256(), h.file(h.clientDir, "actually-cheat.jar", "cheat bytes"));
            s.add(fake);
            s.add(h.selfSeed(h.clientDir));
            return s;
        });
        assertTrue(o.kicked(), () -> h.logLines.toString());
        assertTrue(h.reports.get(0).toJsonLine().contains("PROOF_INVALID"));
    }

    @Test
    void missingScopeIsRejected() throws Exception {
        Harness.Outcome o = h.connect("Partial", this::legitClient, () -> h.clientTrust, EnumSet.of(Scope.MODS));
        assertTrue(o.kicked());
        assertTrue(h.reports.get(0).toJsonLine().contains("SCOPE_MISSING"));
    }

    // ---- audit ----

    @Test
    void auditModeLogsButAllows() throws Exception {
        h.policy = PolicyConfig.builder().mode(EnforcementMode.AUDIT).build();
        Harness.Outcome o = h.connect("Tester", () -> {
            List<EntrySeed> s = legitClient();
            s.add(h.seed(EntryKind.MOD, "wurst", "7.0", h.file(h.clientDir, "wurst.jar", "cheat bytes")));
            return s;
        });
        assertTrue(o.allowed);
        assertFalse(o.kicked());
        assertEquals(1, h.reports.size());
        assertEquals(ServerVerdict.Status.AUDIT_ALLOWED, o.client.verdict().orElseThrow().status());
        assertTrue(h.reports.get(0).consoleLines().get(0).contains("AUDIT_ALLOWED"));
    }

    // ---- クライアント側の失敗 ----

    @Test
    void clientWithoutATrustFileAbortsWithAHelpfulMessage() throws Exception {
        Harness.Outcome o = h.connect("NoTrust", this::legitClient, () -> new TrustStore(List.of()), EnumSet.allOf(Scope.class));
        assertEquals(1, o.aborts.size());
        assertTrue(o.aborts.get(0).contains("信頼ファイル"));
        assertFalse(o.allowed);
        // サーバーは応答が来ないのでタイムアウトで切断する
        o.server.onTimeout();
        assertEquals(1, o.kicks.size());
        assertTrue(o.kicks.get(0).contains("タイムアウト"));
    }

    @Test
    void trustFileOfAnotherServerIsNotAccepted() throws Exception {
        TrustStore other = new TrustStore(List.of(
                new TrustFile("other", Ed25519Identity.generate(Harness.RND).publicKey(), PackSecret.generate(Harness.RND))));
        Harness.Outcome o = h.connect("Wrong", this::legitClient, () -> other, EnumSet.allOf(Scope.class));
        assertEquals(1, o.aborts.size());
        assertFalse(o.allowed);
    }

    @Test
    void clientWithStaleSecretIsKickedWithoutLeakingWhy() throws Exception {
        // 公開鍵は合っているが pack_secret が古い/違う(信頼ファイルが古い・偽造)
        TrustStore stale = new TrustStore(List.of(new TrustFile("stale", h.identity.publicKey(), PackSecret.generate(Harness.RND))));
        Harness.Outcome o = h.connect("Stale", this::legitClient, () -> stale, EnumSet.allOf(Scope.class));
        assertTrue(o.kicked());
        assertTrue(o.kicks.get(0).contains("MC2S-"));
        assertTrue(h.logLines.stream().anyMatch(l -> l.contains("UNKNOWN_SECRET")));
        assertFalse(o.kicks.get(0).contains("SECRET"), "the player-facing message must not explain what failed");
    }

    // ---- サーバー側の失敗はすべて閉じる ----

    @Test
    void timeoutWithoutAnyAnswerKicks() throws Exception {
        ServerContext ctx = h.serverContext();
        List<String> kicks = new ArrayList<>();
        ServerVerification v = new ServerVerification(
                ctx,
                new ServerVerification.Player("Silent", java.util.UUID.randomUUID(), "1.2.3.4"),
                new ServerVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {}

                    @Override
                    public void kick(String message) {
                        kicks.add(message);
                    }

                    @Override
                    public void allow() {
                        throw new AssertionError("must not allow");
                    }
                });
        v.start();
        v.onTimeout();
        v.onTimeout(); // 二重に呼んでも 1 回だけ
        assertEquals(1, kicks.size());
        assertTrue(h.logLines.stream().anyMatch(l -> l.contains("Silent")));
    }

    @Test
    void clientLackingTheModIsKicked() throws Exception {
        ServerContext ctx = h.serverContext();
        List<String> kicks = new ArrayList<>();
        ServerVerification v = new ServerVerification(
                ctx,
                new ServerVerification.Player("Vanilla", java.util.UUID.randomUUID(), "1.2.3.4"),
                new ServerVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {}

                    @Override
                    public void kick(String message) {
                        kicks.add(message);
                    }

                    @Override
                    public void allow() {
                        throw new AssertionError("must not allow");
                    }
                });
        v.onClientLacksMod();
        assertEquals(1, kicks.size());
        assertTrue(kicks.get(0).contains("mcC2S"));
    }

    @Test
    void garbageChunksKickAndLaterInputIsIgnored() throws Exception {
        ServerContext ctx = h.serverContext();
        List<String> kicks = new ArrayList<>();
        ServerVerification v = new ServerVerification(
                ctx,
                new ServerVerification.Player("Fuzzer", java.util.UUID.randomUUID(), "1.2.3.4"),
                new ServerVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {}

                    @Override
                    public void kick(String message) {
                        kicks.add(message);
                    }

                    @Override
                    public void allow() {
                        throw new AssertionError("must not allow");
                    }
                });
        v.start();
        v.onChunk(new byte[] {1, 2, 3});
        assertEquals(1, kicks.size());
        v.onChunk(new byte[] {9});
        v.onTimeout();
        assertEquals(1, kicks.size(), "no double kick after failure");
    }

    @Test
    void corruptedAttestationIsKicked() throws Exception {
        // 正しい形式のチャンクだが中身が乱数(AEAD を通らない)
        ServerContext ctx = h.serverContext();
        List<String> kicks = new ArrayList<>();
        ServerVerification v = new ServerVerification(
                ctx,
                new ServerVerification.Player("Forger", java.util.UUID.randomUUID(), "1.2.3.4"),
                new ServerVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {}

                    @Override
                    public void kick(String message) {
                        kicks.add(message);
                    }

                    @Override
                    public void allow() {
                        throw new AssertionError("must not allow");
                    }
                });
        v.start();
        byte[] junk = new byte[200];
        Harness.RND.nextBytes(junk);
        for (Fragmenter.Chunk c : Fragmenter.split(Fragmenter.TYPE_ATTESTATION, junk, 28_000)) {
            v.onChunk(c.encode());
        }
        assertEquals(1, kicks.size());
        assertTrue(kicks.get(0).contains("MC2S-"));
    }

    @Test
    void fullQueueRejectsWithBusyMessage() throws Exception {
        h.serverWorker = r -> {
            throw new RejectedExecutionException("full");
        };
        Harness.Outcome o = h.connect("Crowd", this::legitClient);
        assertEquals(1, o.kicks.size());
        assertTrue(o.kicks.get(0).contains("混み合って"));
    }

    @Test
    void unexpectedErrorsFailClosed() throws Exception {
        // 参照ファイルの解決で RuntimeException が出ても、通してしまわない
        h.policy = PolicyConfig.builder().proofRatePercent(100).build();
        h.referencesOverride = (kind, sha) -> {
            throw new IllegalStateException("boom");
        };
        Harness.Outcome o = h.connect("Boom", this::legitClient);
        assertFalse(o.allowed, "an internal error must never result in an allow");
        assertEquals(1, o.kicks.size());
        assertTrue(o.kicks.get(0).contains("MC2S-"));
        assertTrue(h.logLines.stream().anyMatch(l -> l.startsWith("ERROR")));
    }

    // ---- 規模 ----

    @Test
    void largeModpackFitsTheRealPacketLimit() throws Exception {
        List<EntrySeed> clientMods = new ArrayList<>();
        for (int i = 0; i < 3000; i++) {
            clientMods.add(h.seed(EntryKind.MOD, "mod" + i, "1.0", h.file(h.clientDir, "m" + i + ".jar", "mod " + i)));
            h.serverOwn.add(h.seed(EntryKind.MOD, "mod" + i, "1.0", h.file(h.serverDir, "m" + i + ".jar", "mod " + i)));
        }
        Harness.Outcome o = h.connect("Modpack", () -> {
            List<EntrySeed> s = legitClient();
            s.addAll(clientMods);
            return s;
        });
        assertTrue(o.clientToServerChunks > 3, "must have been split into several chunks");
        assertTrue(o.largestClientChunk <= Harness.MAX_SERVERBOUND_PAYLOAD);
        assertTrue(o.allowed, () -> o.kicks + " " + o.aborts);
    }
}
