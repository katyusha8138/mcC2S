package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;

/**
 * 「今この瞬間にそのファイルの中身を持っている」ことの証明(セッション束縛の測定)。
 * <pre>proof = HMAC(k_proof, label || kind || sha256 || ファイルの全バイト)</pre>
 * k_proof はセッション固有なので事前計算・使い回しができない。サーバーが同じバイト列(参照ファイル)を
 * 持っている項目についてのみ検証できる(サーバー自身の Mod、mcC2S 本体、運営者が置いた参照 jar)。
 */
public final class ProofContext {
    private final byte[] key;
    private final byte[] nonceS;
    private final int ratePercent;

    ProofContext(byte[] key, byte[] nonceS, int ratePercent) {
        this.key = key;
        this.nonceS = nonceS;
        this.ratePercent = ratePercent;
    }

    /**
     * この項目に証明が必須か。SELF は常に必須。それ以外はサーバーが送った nonce から決まる
     * 決定的なサンプリングで、割合 {@code ratePercent}% が選ばれる(クライアントは事前に予測できない)。
     */
    public boolean required(EntryKind kind, String sha256Hex) {
        if (kind == EntryKind.SELF) {
            return true;
        }
        if (ratePercent <= 0) {
            return false;
        }
        if (ratePercent >= 100) {
            return true;
        }
        byte[] h = Digests.hmac(
                nonceS,
                Labels.PROOF_SELECT.getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) kind.code()},
                Digests.fromHex(sha256Hex));
        int v = (((h[0] & 0xFF) << 8) | (h[1] & 0xFF)) % 100;
        return v < ratePercent;
    }

    public byte[] prove(EntryKind kind, String sha256Hex, InputStream data) throws IOException {
        try {
            Mac mac = Digests.newMac(key);
            mac.update(Labels.PROOF.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) kind.code());
            mac.update(Digests.fromHex(sha256Hex));
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = data.read(buf)) > 0) {
                mac.update(buf, 0, n);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public boolean verify(EntryKind kind, String sha256Hex, byte[] proof, InputStream data) throws IOException {
        return proof != null && Digests.equal(prove(kind, sha256Hex, data), proof);
    }
}
