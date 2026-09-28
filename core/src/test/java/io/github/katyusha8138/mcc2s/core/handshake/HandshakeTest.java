// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.HandshakeException.Reason;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class HandshakeTest {
    private final Fixtures fx = Fixtures.create();

    private static Reason reasonOf(HandshakeThrowing t) {
        return assertThrows(HandshakeException.class, t::run).reason();
    }

    @FunctionalInterface
    private interface HandshakeThrowing {
        void run() throws HandshakeException;
    }

    private static Entry mod(String id, String seed) {
        return new Entry(EntryKind.MOD, id, "1.0", Fixtures.sha(seed));
    }

    private static Entry self() {
        return new Entry(EntryKind.SELF, "mcc2s", "0.1.0", Fixtures.sha("mcc2s-official"));
    }

    // ---- 正常系 ----

    @Test
    void happyPathDeliversManifestAndVerdict() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ClientHandshake client = fx.newClient(server);
        assertEquals(Fixtures.ALL_SCOPES, client.requestedScopes());

        Manifest sent = Fixtures.manifest(Fixtures.ALL_SCOPES, self(), mod("jei", "jei"));
        byte[] attestation = client.attest(sent);
        ServerHandshake.Opened opened = server.open(attestation);
        assertEquals(sent, opened.manifest());

        byte[] refId = new byte[ServerVerdict.REF_ID_LEN];
        Fixtures.RND.nextBytes(refId);
        ServerVerdict verdict = new ServerVerdict(ServerVerdict.Status.ALLOWED, 0, refId, "ok", 600);
        ServerVerdict got = client.readVerdict(opened.sealVerdict(verdict));
        assertEquals(ServerVerdict.Status.ALLOWED, got.status());
        assertEquals("ok", got.message());
        assertEquals(600, got.reverifySeconds());
        assertArrayEquals(refId, got.refId());
    }

    @Test
    void everyHandshakeUsesFreshKeysAndNonces() throws Exception {
        ServerHandshake a = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ServerHandshake b = fx.newServer(Fixtures.ALL_SCOPES, 0);
        assertFalse(java.util.Arrays.equals(a.challenge(), b.challenge()));
        Manifest m = Fixtures.manifest(Fixtures.ALL_SCOPES, self());
        byte[] x = fx.newClient(a).attest(m);
        byte[] y = fx.newClient(a).attest(m);
        assertFalse(java.util.Arrays.equals(x, y)); // 同じ内容でも暗号文・鍵・nonce は毎回異なる
    }

    @Test
    void largeManifestSurvivesFragmentation() throws Exception {
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < 3000; i++) {
            entries.add(mod("mod" + i, "m" + i));
        }
        entries.add(self());
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ClientHandshake client = fx.newClient(server);
        byte[] attestation = client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, entries));
        assertTrue(attestation.length > 100_000, "should exceed a single 32KB payload");

        Reassembler re = new Reassembler(Fragmenter.TYPE_ATTESTATION, 4 * 1024 * 1024, 256);
        byte[] whole = null;
        for (Fragmenter.Chunk c : Fragmenter.split(Fragmenter.TYPE_ATTESTATION, attestation, 30_000)) {
            assertTrue(c.encode().length <= 32_767, "each chunk must fit the serverbound payload limit");
            whole = re.accept(Fragmenter.Chunk.decode(c.encode())).orElse(null);
        }
        assertEquals(3001, server.open(whole).manifest().entries().size());
    }

    // ---- 認証(pack_secret / サーバー鍵ピン留め) ----

    @Test
    void clientWithoutMatchingTrustFileCannotAnswer() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        Fixtures stranger = Fixtures.create(); // 別サーバーの信頼ファイルしか持たない
        assertEquals(
                Reason.UNTRUSTED_SERVER,
                reasonOf(() -> ClientHandshake.accept(
                        stranger.trust, server.challenge(), Contexts.player(fx.player), Fixtures.RND)));
    }

    @Test
    void attackerKnowingServerKeyButNotPackSecretIsRejected() throws Exception {
        // 攻撃者はサーバー公開鍵(識別・公開情報)は知っているが pack_secret は知らない
        PackSecret guessed = PackSecret.generate(Fixtures.RND);
        TrustStore attackerTrust =
                new TrustStore(List.of(new TrustFile("x", fx.identity.publicKey(), guessed)));
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ClientHandshake attacker =
                ClientHandshake.accept(attackerTrust, server.challenge(), Contexts.player(fx.player), Fixtures.RND);
        byte[] att = attacker.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self()));
        assertEquals(Reason.UNKNOWN_SECRET, reasonOf(() -> server.open(att)));
    }

    @Test
    void attackerWhoForgesSecretIdStillFailsAuthentication() throws Exception {
        // 正規の secretId を名乗っても、鍵導出に pack_secret が入るので AEAD 認証を通れない
        PackSecret wrong = PackSecret.generate(Fixtures.RND);
        TrustStore attackerTrust = new TrustStore(List.of(new TrustFile("x", fx.identity.publicKey(), wrong)));
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ClientHandshake attacker =
                ClientHandshake.accept(attackerTrust, server.challenge(), Contexts.player(fx.player), Fixtures.RND);
        byte[] att = attacker.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self()));
        // secretId 部分(先頭 1 バイトの version の直後 8 バイト)を正規のものに書き換える
        byte[] forged = att.clone();
        System.arraycopy(fx.secret.id(), 0, forged, 1, PackSecret.ID_LEN);
        assertEquals(Reason.AUTH_FAILED, reasonOf(() -> server.open(forged)));
    }

    @Test
    void fakeServerCannotImpersonate() throws Exception {
        // 攻撃者が自分の鍵でチャレンジを作り、正規サーバーの keyId を詐称する
        Fixtures attacker = Fixtures.create();
        ServerHandshake fake = attacker.newServer(Fixtures.ALL_SCOPES, 0);
        byte[] ch = fake.challenge();
        System.arraycopy(fx.identity.keyId(), 0, ch, 2, Ed25519Identity.KEY_ID_LEN); // keyId を書き換え
        byte[] forged = ch;
        assertEquals(
                Reason.BAD_SIGNATURE,
                reasonOf(() -> ClientHandshake.accept(fx.trust, forged, Contexts.player(fx.player), Fixtures.RND)));
    }

    // ---- チャレンジ改ざん・ダウングレード・コンテキスト束縛 ----

    @Test
    void everyChallengeByteIsAuthenticated() throws Exception {
        byte[] original = fx.newServer(Fixtures.ALL_SCOPES, 20).challenge();
        for (int i = 0; i < original.length; i++) {
            byte[] tampered = original.clone();
            tampered[i] ^= 0x01;
            HandshakeException e = assertThrows(
                    HandshakeException.class,
                    () -> ClientHandshake.accept(fx.trust, tampered, Contexts.player(fx.player), Fixtures.RND),
                    "byte " + i + " must be protected");
            // keyId 部分の改ざんは「未知のサーバー」、それ以外は署名不正/構文/版違いのいずれかで必ず拒否される
            assertTrue(
                    e.reason() == Reason.BAD_SIGNATURE
                            || e.reason() == Reason.UNTRUSTED_SERVER
                            || e.reason() == Reason.UNSUPPORTED_VERSION
                            || e.reason() == Reason.MALFORMED,
                    "byte " + i + ": " + e.reason());
        }
    }

    @Test
    void scopeReductionByManInTheMiddleIsDetected() throws Exception {
        // 中間者が「報告範囲」を減らしてチェックを緩めようとする
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        byte[] ch = server.challenge();
        int scopeMaskOffset = 1 + 1 + 8 + 32 + 32;
        ch[scopeMaskOffset] = (byte) Scope.MODS.bit();
        byte[] tampered = ch;
        assertEquals(
                Reason.BAD_SIGNATURE,
                reasonOf(() -> ClientHandshake.accept(fx.trust, tampered, Contexts.player(fx.player), Fixtures.RND)));
    }

    @Test
    void versionDowngradeIsRejected() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        byte[] ch = server.challenge();
        ch[0] = 0; // 旧版を装う
        byte[] tampered = ch;
        assertEquals(
                Reason.UNSUPPORTED_VERSION,
                reasonOf(() -> ClientHandshake.accept(fx.trust, tampered, Contexts.player(fx.player), Fixtures.RND)));

        // 添付側の版も同様
        ClientHandshake client = fx.newClient(server);
        byte[] att = client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self()));
        att[0] = 0;
        byte[] badAtt = att;
        assertEquals(Reason.UNSUPPORTED_VERSION, reasonOf(() -> server.open(badAtt)));
    }

    @Test
    void handshakeIsBoundToTheConnectionContext() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0); // fx.player 用のチャレンジ
        UUID other = UUID.randomUUID();
        assertEquals(
                Reason.BAD_SIGNATURE,
                reasonOf(() -> ClientHandshake.accept(fx.trust, server.challenge(), Contexts.player(other), Fixtures.RND)));
    }

    // ---- 添付の改ざん・リプレイ ----

    @Test
    void replayedAttestationFailsAgainstNewChallenge() throws Exception {
        // 正規プレイヤーの添付を盗聴し、別のセッション(=新しいチャレンジ)へ再送する
        Fixtures.Session legit = fx.run(Fixtures.ALL_SCOPES, 0, c -> List.of(self()));
        ServerHandshake fresh = fx.newServer(Fixtures.ALL_SCOPES, 0);
        assertEquals(Reason.AUTH_FAILED, reasonOf(() -> fresh.open(legit.attestation)));
    }

    @Test
    void sameHandshakeCannotBeUsedTwice() throws Exception {
        Fixtures.Session legit = fx.run(Fixtures.ALL_SCOPES, 0, c -> List.of(self()));
        assertEquals(Reason.REPLAY, reasonOf(() -> legit.server.open(legit.attestation)));
    }

    @Test
    void failedAttemptAlsoConsumesTheHandshake() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        assertEquals(Reason.MALFORMED, reasonOf(() -> server.open(new byte[3])));
        ClientHandshake client = fx.newClient(server);
        byte[] good = client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self()));
        assertEquals(Reason.REPLAY, reasonOf(() -> server.open(good))); // 総当たりの足場にさせない
    }

    @Test
    void everyAttestationByteIsAuthenticated() throws Exception {
        ServerHandshake probe = fx.newServer(Fixtures.ALL_SCOPES, 0);
        byte[] att = fx.newClient(probe).attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self(), mod("a", "a")));
        // 各バイトを 1 ビット反転しても、サーバーは(新規ハンドシェイクでは別鍵なので)必ず拒否する。
        // 同一ハンドシェイクでの検証のため、毎回チャレンジからやり直す。
        for (int i = 0; i < att.length; i += 7) {
            ServerHandshake s = fx.newServer(Fixtures.ALL_SCOPES, 0);
            byte[] good = fx.newClient(s).attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self(), mod("a", "a")));
            byte[] bad = good.clone();
            bad[i] ^= 0x01;
            HandshakeException e = assertThrows(HandshakeException.class, () -> s.open(bad), "byte " + i);
            assertTrue(
                    e.reason() == Reason.AUTH_FAILED
                            || e.reason() == Reason.UNKNOWN_SECRET
                            || e.reason() == Reason.UNSUPPORTED_VERSION
                            || e.reason() == Reason.MALFORMED,
                    "byte " + i + ": " + e.reason());
        }
        assertTrue(att.length > 0);
    }

    @Test
    void lowOrderEphemeralKeyFromClientIsRejected() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        byte[] att = new WireWriter()
                .u8(1)
                .fixed(fx.secret.id(), PackSecret.ID_LEN)
                .fixed(new byte[32], 32) // u = 0
                .fixed(new byte[32], 32)
                .blob(new byte[64], 1 << 20)
                .toByteArray();
        assertEquals(Reason.AUTH_FAILED, reasonOf(() -> server.open(att)));
    }

    @Test
    void garbageAndTruncatedInputsAreRejectedCleanly() throws Exception {
        for (int len : new int[] {0, 1, 8, 40, 200}) {
            byte[] junk = new byte[len];
            Fixtures.RND.nextBytes(junk);
            ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
            assertThrows(HandshakeException.class, () -> server.open(junk));
            assertThrows(
                    HandshakeException.class,
                    () -> ClientHandshake.accept(fx.trust, junk, Contexts.player(fx.player), Fixtures.RND));
        }
    }

    // ---- 判定結果(Verdict) ----

    @Test
    void verdictCannotBeForgedOrTransplanted() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ClientHandshake client = fx.newClient(server);
        assertEquals(Reason.INTERNAL, reasonOf(() -> client.readVerdict(new byte[10]))); // attest 前

        ServerHandshake.Opened opened = server.open(client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self())));
        ServerVerdict deny = new ServerVerdict(ServerVerdict.Status.DENIED, 1, new byte[8], "no", 0);
        byte[] sealed = opened.sealVerdict(deny);

        // 1 ビット改ざん
        byte[] bad = sealed.clone();
        bad[bad.length - 1] ^= 1;
        assertEquals(Reason.AUTH_FAILED, reasonOf(() -> client.readVerdict(bad)));

        // 別セッションの「許可」判定を横取りして差し込む(中間者が DENIED を ALLOWED にすり替える想定)
        Fixtures.Session other = fx.run(Fixtures.ALL_SCOPES, 0, c -> List.of(self()));
        byte[] otherAllowed = other.opened.sealVerdict(
                new ServerVerdict(ServerVerdict.Status.ALLOWED, 0, new byte[8], "ok", 0));
        assertEquals(Reason.AUTH_FAILED, reasonOf(() -> client.readVerdict(otherAllowed)));

        assertEquals(ServerVerdict.Status.DENIED, client.readVerdict(sealed).status());
    }

    @Test
    void attestTwiceIsRefused() throws Exception {
        ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, 0);
        ClientHandshake client = fx.newClient(server);
        client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self()));
        assertEquals(Reason.REPLAY, reasonOf(() -> client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self()))));
    }

    // ---- 測定証明(Proof) ----

    @Test
    void proofBindsToSessionAndContent() throws Exception {
        byte[] jar = "pretend jar bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String sha = Digests.hex(Digests.sha256(jar));

        Fixtures.Session s = fx.run(Fixtures.ALL_SCOPES, 100, c -> {
            try {
                byte[] proof = c.proofs().prove(EntryKind.MOD, sha, new ByteArrayInputStream(jar));
                return List.of(self(), new Entry(EntryKind.MOD, "m", "1", sha, proof));
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        });
        Entry sent = s.opened.manifest().entries().get(1);
        assertTrue(s.opened.proofs().verify(EntryKind.MOD, sha, sent.proof(), new ByteArrayInputStream(jar)));

        // 内容が違うファイルでは一致しない(ハッシュだけ知っていてもファイルを持っていなければ作れない)
        byte[] other = "tampered jar bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertFalse(s.opened.proofs().verify(EntryKind.MOD, sha, sent.proof(), new ByteArrayInputStream(other)));

        // 別セッションでは同じ証明が通らない(リプレイ不可)
        Fixtures.Session s2 = fx.run(Fixtures.ALL_SCOPES, 100, c -> List.of(self()));
        assertFalse(s2.opened.proofs().verify(EntryKind.MOD, sha, sent.proof(), new ByteArrayInputStream(jar)));

        // 種別の付け替えも不可
        assertFalse(s.opened.proofs().verify(EntryKind.LIBRARY, sha, sent.proof(), new ByteArrayInputStream(jar)));
    }

    @Test
    void proofSelectionAgreesOnBothSidesAndHonoursRate() throws Exception {
        for (int rate : new int[] {0, 20, 50, 100}) {
            ServerHandshake server = fx.newServer(Fixtures.ALL_SCOPES, rate);
            ClientHandshake client = fx.newClient(server);
            ServerHandshake.Opened opened = server.open(client.attest(Fixtures.manifest(Fixtures.ALL_SCOPES, self())));
            int selected = 0;
            for (int i = 0; i < 1000; i++) {
                String sha = Fixtures.sha("e" + i);
                boolean c = client.proofs().required(EntryKind.MOD, sha);
                assertEquals(c, opened.proofs().required(EntryKind.MOD, sha));
                if (c) {
                    selected++;
                }
            }
            assertTrue(client.proofs().required(EntryKind.SELF, Fixtures.sha("any")), "SELF is always required");
            if (rate == 0) {
                assertEquals(0, selected);
            } else if (rate == 100) {
                assertEquals(1000, selected);
            } else {
                assertTrue(Math.abs(selected - rate * 10) < 100, "rate " + rate + " selected " + selected);
            }
        }
    }

    @Test
    void selectionIsUnpredictableAcrossSessions() throws Exception {
        Set<String> a = new java.util.HashSet<>();
        Set<String> b = new java.util.HashSet<>();
        ClientHandshake c1 = fx.newClient(fx.newServer(Fixtures.ALL_SCOPES, 50));
        ClientHandshake c2 = fx.newClient(fx.newServer(Fixtures.ALL_SCOPES, 50));
        for (int i = 0; i < 200; i++) {
            String sha = Fixtures.sha("p" + i);
            if (c1.proofs().required(EntryKind.MOD, sha)) {
                a.add(sha);
            }
            if (c2.proofs().required(EntryKind.MOD, sha)) {
                b.add(sha);
            }
        }
        assertFalse(a.equals(b), "different nonces must select different subsets");
    }
}
