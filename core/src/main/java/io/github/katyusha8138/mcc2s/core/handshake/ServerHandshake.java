package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Aead;
import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Set;
import javax.crypto.AEADBadTagException;

/**
 * サーバー側の 1 回限りのハンドシェイク(1 接続・1 チャレンジ)。
 * <ol>
 *   <li>{@link #start} でチャレンジを作り、{@link #challenge()} を送る</li>
 *   <li>返ってきた添付を {@link #open} で復号・検証する(失敗しても成功しても 1 回で消費される)</li>
 *   <li>ポリシー評価後、{@link Opened#sealVerdict} で結果を暗号化して返す</li>
 * </ol>
 * 再検証は新しいインスタンス(=新しい nonce と一時鍵)で行う。
 */
public final class ServerHandshake {
    private final PackSecrets secrets;
    private final byte[] nonceS;
    private final int proofRatePercent;
    private final byte[] th1;
    private final byte[] challengeBytes;
    private PrivateKey ephemeralPrivate;
    private boolean consumed;

    private ServerHandshake(
            PackSecrets secrets,
            byte[] nonceS,
            int proofRatePercent,
            byte[] th1,
            byte[] challengeBytes,
            PrivateKey ephemeralPrivate) {
        this.secrets = secrets;
        this.nonceS = nonceS;
        this.proofRatePercent = proofRatePercent;
        this.th1 = th1;
        this.challengeBytes = challengeBytes;
        this.ephemeralPrivate = ephemeralPrivate;
    }

    /**
     * @param context 接続に束縛する追加データ(通常はプレイヤー UUID。{@link Contexts#player})。クライアント側と一致しなければ署名検証に失敗する
     * @param proofRatePercent 測定証明を要求する項目の割合(0〜100)。SELF は常に要求される
     */
    public static ServerHandshake start(
            Ed25519Identity identity,
            PackSecrets secrets,
            Set<Scope> scopes,
            int proofRatePercent,
            byte[] context,
            SecureRandom rnd)
            throws GeneralSecurityException {
        if (proofRatePercent < 0 || proofRatePercent > 100) {
            throw new IllegalArgumentException("proofRatePercent must be 0..100");
        }
        KeyPair eph = Curves.generateX25519(rnd);
        byte[] nonce = new byte[ServerChallenge.NONCE_LEN];
        rnd.nextBytes(nonce);
        ServerChallenge unsigned = new ServerChallenge(
                Labels.VERSION,
                Labels.SUITE,
                identity.keyId(),
                Curves.rawPublic(eph.getPublic()),
                nonce,
                Scope.toMask(scopes),
                proofRatePercent,
                new byte[Curves.SIG_LEN]);
        byte[] th1 = Digests.framed(Labels.TH1, context, unsigned.unsigned());
        byte[] sig = identity.sign(Digests.framed(Labels.CHALLENGE_SIG, th1));
        ServerChallenge signed = new ServerChallenge(
                unsigned.version,
                unsigned.suite,
                unsigned.keyId,
                unsigned.ephemeralKey,
                unsigned.nonce,
                unsigned.scopeMask,
                unsigned.proofRatePercent,
                sig);
        return new ServerHandshake(secrets, nonce, proofRatePercent, th1, signed.encode(), eph.getPrivate());
    }

    public byte[] challenge() {
        return challengeBytes.clone();
    }

    /**
     * クライアントの添付を復号して検証する。認証(pack_secret・セッション束縛)に失敗したものは
     * {@link HandshakeException} になり、マニフェストは一切パースされない。
     */
    public synchronized Opened open(byte[] attestationBytes) throws HandshakeException {
        if (consumed) {
            throw new HandshakeException(HandshakeException.Reason.REPLAY, "handshake already used");
        }
        consumed = true;
        PrivateKey eph = ephemeralPrivate;
        ephemeralPrivate = null;

        ClientAttestation att;
        try {
            att = ClientAttestation.decode(attestationBytes);
        } catch (WireException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, e.getMessage());
        }
        if (att.version != Labels.VERSION) {
            throw new HandshakeException(HandshakeException.Reason.UNSUPPORTED_VERSION, "version " + att.version);
        }
        PackSecret secret = secrets.find(att.secretId)
                .orElseThrow(() -> new HandshakeException(HandshakeException.Reason.UNKNOWN_SECRET, "unknown secret id"));

        byte[] plaintext;
        byte[] th2;
        SessionKeys keys;
        try {
            byte[] ecdh = Curves.x25519(eph, att.ephemeralKey);
            th2 = Digests.framed(Labels.TH2, th1, new byte[] {(byte) Labels.VERSION}, att.secretId, att.ephemeralKey, att.nonce);
            keys = SessionKeys.derive(ecdh, secret.value(), nonceS, att.nonce, th2);
            plaintext = Aead.open(keys.c2s, 0, th2, att.ciphertext);
        } catch (AEADBadTagException e) {
            throw new HandshakeException(HandshakeException.Reason.AUTH_FAILED, "authentication failed");
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(HandshakeException.Reason.AUTH_FAILED, "key agreement failed", e);
        }

        Manifest manifest;
        try {
            manifest = Manifest.decode(plaintext);
        } catch (WireException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, e.getMessage());
        }
        byte[] th3 = Digests.framed(Labels.TH3, th2, att.ciphertext);
        return new Opened(manifest, new ProofContext(keys.proof, nonceS, proofRatePercent), keys.s2c, th3);
    }

    /** 認証済みのクライアント添付。 */
    public static final class Opened {
        private final Manifest manifest;
        private final ProofContext proofs;
        private final byte[] s2cKey;
        private final byte[] th3;

        private Opened(Manifest manifest, ProofContext proofs, byte[] s2cKey, byte[] th3) {
            this.manifest = manifest;
            this.proofs = proofs;
            this.s2cKey = s2cKey;
            this.th3 = th3;
        }

        public Manifest manifest() {
            return manifest;
        }

        /** 項目ごとの測定証明を検証するためのコンテキスト。 */
        public ProofContext proofs() {
            return proofs;
        }

        public byte[] sealVerdict(ServerVerdict verdict) throws HandshakeException {
            try {
                byte[] ct = Aead.seal(s2cKey, 0, th3, verdict.encode());
                return new WireWriter()
                        .u8(Labels.VERSION)
                        .blob(ct, 4096)
                        .toByteArray();
            } catch (GeneralSecurityException e) {
                throw new HandshakeException(HandshakeException.Reason.INTERNAL, "seal failed", e);
            }
        }
    }
}
