// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class FilesAndFragmentsTest {
    // ---- 鍵ファイル / 信頼ファイル ----

    @Test
    void identityFileRoundTrip() throws Exception {
        Ed25519Identity id = Ed25519Identity.generate(Fixtures.RND);
        Ed25519Identity back = Ed25519Identity.parse(id.toFileText());
        assertArrayEquals(id.publicKey(), back.publicKey());
        assertArrayEquals(id.keyId(), back.keyId());
        byte[] msg = {1, 2, 3};
        assertTrue(io.github.katyusha8138.mcc2s.core.crypto.Curves.verify(id.publicKey(), msg, back.sign(msg)));
    }

    @Test
    void identityFileWithMismatchedKeysIsRejected() throws Exception {
        Ed25519Identity a = Ed25519Identity.generate(Fixtures.RND);
        Ed25519Identity b = Ed25519Identity.generate(Fixtures.RND);
        String mixed = a.toFileText().split("\n")[0] + "\n"
                + a.toFileText().split("\n")[1] + "\n"
                + b.toFileText().split("\n")[2] + "\n";
        assertThrows(GeneralSecurityException.class, () -> Ed25519Identity.parse(mixed));
    }

    @Test
    void trustFileRoundTripAndTamperDetection() throws Exception {
        Ed25519Identity id = Ed25519Identity.generate(Fixtures.RND);
        TrustFile tf = new TrustFile("My Server", id.publicKey(), PackSecret.generate(Fixtures.RND));
        TrustFile back = TrustFile.parse(tf.toText());
        assertEquals("My Server", back.label());
        assertArrayEquals(tf.serverPublicKey(), back.serverPublicKey());
        assertArrayEquals(tf.packSecret().value(), back.packSecret().value());
        assertArrayEquals(id.keyId(), back.serverKeyId());

        // ラベルを書き換えるとチェックサムで検出される(コピペ事故・手編集の検出)
        String edited = tf.toText().replace("My Server", "Evil Server");
        assertThrows(GeneralSecurityException.class, () -> TrustFile.parse(edited));
        // ヘッダ違い・欠落
        assertThrows(GeneralSecurityException.class, () -> TrustFile.parse("nonsense\n"));
        assertThrows(GeneralSecurityException.class, () -> TrustFile.parse(TrustFile.HEADER + "\nlabel = x\n"));
    }

    @Test
    void packSecretIdDoesNotRevealSecretAndRotationWorks() throws Exception {
        PackSecret oldOne = PackSecret.generate(Fixtures.RND);
        PackSecret current = PackSecret.generate(Fixtures.RND);
        PackSecrets set = new PackSecrets(List.of(current, oldOne));
        assertTrue(set.find(oldOne.id()).isPresent());
        assertTrue(set.find(current.id()).isPresent());
        assertFalse(set.find(new byte[8]).isPresent());
        assertFalse(new String(oldOne.id(), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains(new String(oldOne.value(), java.nio.charset.StandardCharsets.ISO_8859_1)));
        assertThrows(IllegalArgumentException.class, () -> new PackSecrets(List.of()));
    }

    // ---- 分割・再構成 ----

    @Test
    void splitAndReassembleRoundTrip() {
        byte[] msg = new byte[100_000];
        Fixtures.RND.nextBytes(msg);
        List<Fragmenter.Chunk> chunks = Fragmenter.split(Fragmenter.TYPE_ATTESTATION, msg, 30_000);
        assertEquals(4, chunks.size());
        Reassembler r = new Reassembler(Fragmenter.TYPE_ATTESTATION, 200_000, 16);
        Optional<byte[]> out = Optional.empty();
        for (Fragmenter.Chunk c : chunks) {
            assertTrue(out.isEmpty());
            out = r.accept(Fragmenter.Chunk.decode(c.encode()));
        }
        assertArrayEquals(msg, out.orElseThrow());
    }

    @Test
    void emptyMessageIsOneChunk() {
        List<Fragmenter.Chunk> chunks = Fragmenter.split(Fragmenter.TYPE_VERDICT, new byte[0], 100);
        assertEquals(1, chunks.size());
        Reassembler r = new Reassembler(Fragmenter.TYPE_VERDICT, 100, 4);
        assertArrayEquals(new byte[0], r.accept(chunks.get(0)).orElseThrow());
    }

    @Test
    void reassemblerRejectsMisbehavior() {
        byte[] msg = new byte[250];
        List<Fragmenter.Chunk> c = Fragmenter.split(Fragmenter.TYPE_ATTESTATION, msg, 100); // 3 chunks

        // 順序外
        Reassembler r1 = new Reassembler(Fragmenter.TYPE_ATTESTATION, 1000, 8);
        assertThrows(WireException.class, () -> r1.accept(c.get(1)));

        // 重複
        Reassembler r2 = new Reassembler(Fragmenter.TYPE_ATTESTATION, 1000, 8);
        r2.accept(c.get(0));
        assertThrows(WireException.class, () -> r2.accept(c.get(0)));

        // 種別違い
        Reassembler r3 = new Reassembler(Fragmenter.TYPE_VERDICT, 1000, 8);
        assertThrows(WireException.class, () -> r3.accept(c.get(0)));

        // 総量超過(宣言より大きいデータの押し込み)
        Reassembler r4 = new Reassembler(Fragmenter.TYPE_ATTESTATION, 150, 8);
        r4.accept(c.get(0));
        assertThrows(WireException.class, () -> r4.accept(c.get(1)));

        // チャンク数の上限
        Reassembler r5 = new Reassembler(Fragmenter.TYPE_ATTESTATION, 1000, 2);
        assertThrows(WireException.class, () -> r5.accept(c.get(0)));

        // 総数の途中変更
        Reassembler r6 = new Reassembler(Fragmenter.TYPE_ATTESTATION, 1000, 8);
        r6.accept(c.get(0));
        assertThrows(WireException.class, () -> r6.accept(new Fragmenter.Chunk(Fragmenter.TYPE_ATTESTATION, 1, 5, new byte[1])));

        // 完了後の追加
        Reassembler r7 = new Reassembler(Fragmenter.TYPE_ATTESTATION, 1000, 8);
        for (Fragmenter.Chunk ch : c) {
            r7.accept(ch);
        }
        assertThrows(WireException.class, () -> r7.accept(c.get(0)));
    }

    @Test
    void chunkDecodeRejectsGarbage() {
        assertThrows(WireException.class, () -> Fragmenter.Chunk.decode(new byte[3]));
        assertThrows(WireException.class, () -> Fragmenter.Chunk.decode(new byte[] {1, 0, 0, 0, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}));
    }
}
