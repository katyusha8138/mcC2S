package io.github.katyusha8138.mcc2s.core.handshake;

/** プロトコル内の全ドメイン分離ラベル。ラベルが異なれば同じ入力でも出力が衝突しない。 */
final class Labels {
    static final int VERSION = 1;
    static final int SUITE = 1; // X25519 + Ed25519 + HKDF-SHA256 + ChaCha20-Poly1305 + HMAC-SHA256

    static final String TH1 = "mcC2S/v1 th1";
    static final String TH2 = "mcC2S/v1 th2";
    static final String TH3 = "mcC2S/v1 th3";
    static final String CHALLENGE_SIG = "mcC2S/v1 challenge-sig";
    static final String SECRET_ID = "mcC2S/v1 secret-id";
    static final String KEY_ID = "mcC2S/v1 key-id";
    static final String KEY_C2S = "mcC2S/v1 key c2s";
    static final String KEY_S2C = "mcC2S/v1 key s2c";
    static final String KEY_PROOF = "mcC2S/v1 key proof";
    static final String PROOF = "mcC2S/v1 proof";
    static final String PROOF_SELECT = "mcC2S/v1 proof-select";

    private Labels() {}
}
