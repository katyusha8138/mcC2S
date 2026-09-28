// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Aead;
import io.github.katyusha8138.mcc2s.core.crypto.Hkdf;
import java.nio.charset.StandardCharsets;

/**
 * ECDH 共有秘密 + pack_secret から派生するセッション鍵。
 * pack_secret を持たない相手は、ECDH が成立してもこの鍵を再現できない。
 */
final class SessionKeys {
    final byte[] c2s;
    final byte[] s2c;
    final byte[] proof;

    private SessionKeys(byte[] c2s, byte[] s2c, byte[] proof) {
        this.c2s = c2s;
        this.s2c = s2c;
        this.proof = proof;
    }

    static SessionKeys derive(byte[] ecdh, byte[] packSecret, byte[] nonceS, byte[] nonceC, byte[] th2) {
        byte[] prk = Hkdf.extract(concat(nonceS, nonceC), concat(ecdh, packSecret));
        return new SessionKeys(
                expand(prk, Labels.KEY_C2S, th2),
                expand(prk, Labels.KEY_S2C, th2),
                expand(prk, Labels.KEY_PROOF, th2));
    }

    private static byte[] expand(byte[] prk, String label, byte[] th2) {
        return Hkdf.expand(prk, concat(label.getBytes(StandardCharsets.UTF_8), th2), Aead.KEY_LEN);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
