package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.wire.WireReader;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;

/** サーバー→クライアントの最初のメッセージ。Ed25519 署名付き(署名対象にプロトコル版・スイート・スコープを含む)。 */
final class ServerChallenge {
    static final int NONCE_LEN = 32;

    final int version;
    final int suite;
    final byte[] keyId;
    final byte[] ephemeralKey;
    final byte[] nonce;
    final int scopeMask;
    final int proofRatePercent;
    final byte[] signature; // encode() では末尾に付く。unsigned() には含まれない。

    ServerChallenge(
            int version,
            int suite,
            byte[] keyId,
            byte[] ephemeralKey,
            byte[] nonce,
            int scopeMask,
            int proofRatePercent,
            byte[] signature) {
        this.version = version;
        this.suite = suite;
        this.keyId = keyId;
        this.ephemeralKey = ephemeralKey;
        this.nonce = nonce;
        this.scopeMask = scopeMask;
        this.proofRatePercent = proofRatePercent;
        this.signature = signature;
    }

    byte[] unsigned() {
        return new WireWriter()
                .u8(version)
                .u8(suite)
                .fixed(keyId, Ed25519Identity.KEY_ID_LEN)
                .fixed(ephemeralKey, Curves.KEY_LEN)
                .fixed(nonce, NONCE_LEN)
                .u8(scopeMask)
                .u8(proofRatePercent)
                .toByteArray();
    }

    byte[] encode() {
        return new WireWriter().raw(unsigned()).fixed(signature, Curves.SIG_LEN).toByteArray();
    }

    static ServerChallenge decode(byte[] data) {
        WireReader r = new WireReader(data);
        int version = r.u8();
        int suite = r.u8();
        byte[] keyId = r.fixed(Ed25519Identity.KEY_ID_LEN);
        byte[] eph = r.fixed(Curves.KEY_LEN);
        byte[] nonce = r.fixed(NONCE_LEN);
        int scopeMask = r.u8();
        int rate = r.u8();
        byte[] sig = r.fixed(Curves.SIG_LEN);
        r.requireEnd();
        return new ServerChallenge(version, suite, keyId, eph, nonce, scopeMask, rate, sig);
    }
}
