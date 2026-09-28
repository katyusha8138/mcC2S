package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Ed25519 の長期鍵。サーバー識別鍵と、リリース署名鍵の両方に使う。
 * 秘密鍵ファイルはサーバー/リリース担当者のみが保持し、クライアントに配布しない。
 */
public final class Ed25519Identity {
    public static final String FILE_HEADER = "mcc2s-ed25519-identity-v1";
    public static final int KEY_ID_LEN = 8;

    private final byte[] publicKey;
    private final byte[] privateKey;
    private final PrivateKey signingKey;

    private Ed25519Identity(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.signingKey = Curves.ed25519Private(privateKey);
        // 公開鍵と秘密鍵の対応をその場で検証する(ファイル破損・取り違えの検出)
        byte[] probe = "mcC2S/v1 identity-selftest".getBytes(StandardCharsets.UTF_8);
        if (!Curves.verify(publicKey, probe, Curves.sign(signingKey, probe))) {
            throw new GeneralSecurityException("public and private key do not match");
        }
    }

    public static Ed25519Identity generate(SecureRandom rnd) throws GeneralSecurityException {
        KeyPair kp = Curves.generateEd25519(rnd);
        return new Ed25519Identity(Curves.rawPublic(kp.getPublic()), Curves.rawPrivate(kp.getPrivate()));
    }

    public static Ed25519Identity fromRaw(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {
        return new Ed25519Identity(publicKey.clone(), privateKey.clone());
    }

    public byte[] publicKey() {
        return publicKey.clone();
    }

    public byte[] keyId() {
        return keyId(publicKey);
    }

    /** 公開鍵の短い識別子(信頼ファイル検索用)。秘密ではない。 */
    public static byte[] keyId(byte[] publicKey) {
        return Arrays.copyOf(Digests.framed(Labels.KEY_ID, publicKey), KEY_ID_LEN);
    }

    public byte[] sign(byte[] message) throws GeneralSecurityException {
        return Curves.sign(signingKey, message);
    }

    /** 秘密鍵を含むファイル内容。取り扱い注意。 */
    public String toFileText() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return FILE_HEADER + "\n"
                + "public_key = " + enc.encodeToString(publicKey) + "\n"
                + "private_key = " + enc.encodeToString(privateKey) + "\n";
    }

    public static Ed25519Identity parse(String text) throws GeneralSecurityException {
        KeyValueText kv = KeyValueText.parse(text, FILE_HEADER);
        return new Ed25519Identity(kv.base64("public_key", Curves.KEY_LEN), kv.base64("private_key", Curves.KEY_LEN));
    }
}
