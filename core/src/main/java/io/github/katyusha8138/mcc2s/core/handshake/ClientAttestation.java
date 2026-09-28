package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Aead;
import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.wire.WireReader;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;

/** クライアント→サーバー。暗号化されたマニフェスト(AAD = トランスクリプトハッシュ th2)。 */
final class ClientAttestation {
    static final int MAX_CIPHERTEXT = Manifest.MAX_ENCODED_BYTES + Aead.TAG_LEN;

    final int version;
    final byte[] secretId;
    final byte[] ephemeralKey;
    final byte[] nonce;
    final byte[] ciphertext;

    ClientAttestation(int version, byte[] secretId, byte[] ephemeralKey, byte[] nonce, byte[] ciphertext) {
        this.version = version;
        this.secretId = secretId;
        this.ephemeralKey = ephemeralKey;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }

    byte[] encode() {
        return new WireWriter()
                .u8(version)
                .fixed(secretId, PackSecret.ID_LEN)
                .fixed(ephemeralKey, Curves.KEY_LEN)
                .fixed(nonce, ServerChallenge.NONCE_LEN)
                .blob(ciphertext, MAX_CIPHERTEXT)
                .toByteArray();
    }

    static ClientAttestation decode(byte[] data) {
        WireReader r = new WireReader(data);
        int version = r.u8();
        byte[] secretId = r.fixed(PackSecret.ID_LEN);
        byte[] eph = r.fixed(Curves.KEY_LEN);
        byte[] nonce = r.fixed(ServerChallenge.NONCE_LEN);
        byte[] ct = r.blob(MAX_CIPHERTEXT);
        r.requireEnd();
        return new ClientAttestation(version, secretId, eph, nonce, ct);
    }
}
