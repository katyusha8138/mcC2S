package io.github.katyusha8138.mcc2s.core.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 (RFC 8439)。ノンスは 64bit カウンタから作る。
 * 本プロトコルでは鍵は方向・用途ごとにセッション固有で、1 鍵 1 メッセージしか暗号化しない。
 */
public final class Aead {
    public static final int KEY_LEN = 32;
    public static final int TAG_LEN = 16;

    private Aead() {}

    private static byte[] nonce(long counter) {
        byte[] n = new byte[12];
        for (int i = 0; i < 8; i++) {
            n[11 - i] = (byte) (counter >>> (8 * i));
        }
        return n;
    }

    public static byte[] seal(byte[] key, long counter, byte[] aad, byte[] plaintext) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce(counter)));
        c.updateAAD(aad);
        return c.doFinal(plaintext);
    }

    /** 認証失敗時は {@link javax.crypto.AEADBadTagException}。 */
    public static byte[] open(byte[] key, long counter, byte[] aad, byte[] ciphertext) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce(counter)));
        c.updateAAD(aad);
        return c.doFinal(ciphertext);
    }
}
