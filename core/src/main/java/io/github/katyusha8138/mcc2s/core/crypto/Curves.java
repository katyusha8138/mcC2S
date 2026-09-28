// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/** Ed25519 署名と X25519 鍵共有。JDK 標準 JCA のみで、鍵は生の 32 バイト表現で出し入れする。 */
public final class Curves {
    public static final int KEY_LEN = 32;
    public static final int SIG_LEN = 64;

    private static final byte[] X509_ED25519 = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    private static final byte[] X509_X25519 = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
    private static final byte[] PKCS8_ED25519 = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };
    private static final byte[] PKCS8_X25519 = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    };

    private Curves() {}

    public static KeyPair generateEd25519(SecureRandom rnd) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        g.initialize(NamedParameterSpec.ED25519, rnd);
        return g.generateKeyPair();
    }

    public static KeyPair generateX25519(SecureRandom rnd) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("X25519");
        g.initialize(NamedParameterSpec.X25519, rnd);
        return g.generateKeyPair();
    }

    public static byte[] rawPublic(PublicKey key) {
        byte[] enc = key.getEncoded();
        if (enc == null || enc.length != X509_ED25519.length + KEY_LEN) {
            throw new IllegalArgumentException("unexpected public key encoding");
        }
        return Arrays.copyOfRange(enc, X509_ED25519.length, enc.length);
    }

    public static byte[] rawPrivate(PrivateKey key) {
        byte[] enc = key.getEncoded();
        if (enc == null || enc.length != PKCS8_ED25519.length + KEY_LEN) {
            throw new IllegalArgumentException("unexpected private key encoding");
        }
        return Arrays.copyOfRange(enc, PKCS8_ED25519.length, enc.length);
    }

    public static PublicKey ed25519Public(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(X509_ED25519, check(raw))));
    }

    public static PublicKey x25519Public(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(concat(X509_X25519, check(raw))));
    }

    public static PrivateKey ed25519Private(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_ED25519, check(raw))));
    }

    public static PrivateKey x25519Private(byte[] raw) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_X25519, check(raw))));
    }

    public static byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key);
        s.update(message);
        return s.sign();
    }

    /** 不正な鍵・署名長を含むあらゆる失敗を false にする。 */
    public static boolean verify(byte[] rawPublic, byte[] message, byte[] signature) {
        try {
            if (signature == null || signature.length != SIG_LEN) {
                return false;
            }
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(ed25519Public(rawPublic));
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** X25519 の共有秘密。位数の小さい点による全ゼロ出力は拒否する。 */
    public static byte[] x25519(PrivateKey privateKey, byte[] peerRawPublic) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(privateKey);
        ka.doPhase(x25519Public(peerRawPublic), true);
        byte[] secret = ka.generateSecret();
        int acc = 0;
        for (byte b : secret) {
            acc |= b;
        }
        if (acc == 0) {
            throw new GeneralSecurityException("low-order X25519 point");
        }
        return secret;
    }

    private static byte[] check(byte[] raw) {
        if (raw == null || raw.length != KEY_LEN) {
            throw new IllegalArgumentException("key must be " + KEY_LEN + " bytes");
        }
        return raw;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
