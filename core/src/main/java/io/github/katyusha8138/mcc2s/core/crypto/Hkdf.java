// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;

/** RFC 5869 HKDF-SHA256。 */
public final class Hkdf {
    private static final int HASH_LEN = 32;

    private Hkdf() {}

    public static byte[] extract(byte[] salt, byte[] ikm) {
        return Digests.hmac(salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("bad HKDF length");
        }
        try {
            Mac mac = Digests.newMac(prk);
            byte[] out = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            for (int i = 1; pos < length; i++) {
                mac.update(t);
                mac.update(info);
                mac.update((byte) i);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
