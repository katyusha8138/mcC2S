package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Aead;
import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.core.wire.WireReader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;
import javax.crypto.AEADBadTagException;

/**
 * クライアント側の 1 回限りのハンドシェイク。
 * <ol>
 *   <li>{@link #accept}: チャレンジを信頼ファイルのピン留め鍵で検証し、セッション鍵を導出する</li>
 *   <li>{@link #proofs()} で測定証明を作りながらマニフェストを組み立てる</li>
 *   <li>{@link #attest} でマニフェストを暗号化して送る</li>
 *   <li>{@link #readVerdict} で結果を読む</li>
 * </ol>
 */
public final class ClientHandshake {
    private final Set<Scope> requestedScopes;
    private final int proofRatePercent;
    private final byte[] secretId;
    private final byte[] ephemeralPublic;
    private final byte[] nonceC;
    private final byte[] th2;
    private final SessionKeys keys;
    private final ProofContext proofs;
    private boolean attested;
    private byte[] th3;

    private ClientHandshake(
            Set<Scope> requestedScopes,
            int proofRatePercent,
            byte[] secretId,
            byte[] ephemeralPublic,
            byte[] nonceC,
            byte[] th2,
            SessionKeys keys,
            ProofContext proofs) {
        this.requestedScopes = requestedScopes;
        this.proofRatePercent = proofRatePercent;
        this.secretId = secretId;
        this.ephemeralPublic = ephemeralPublic;
        this.nonceC = nonceC;
        this.th2 = th2;
        this.keys = keys;
        this.proofs = proofs;
    }

    /**
     * @param context サーバー側と同じ束縛データ({@link Contexts#player})。一致しなければ署名検証に失敗する
     */
    public static ClientHandshake accept(TrustStore trust, byte[] challengeBytes, byte[] context, SecureRandom rnd)
            throws HandshakeException {
        ServerChallenge c;
        try {
            c = ServerChallenge.decode(challengeBytes);
        } catch (WireException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, e.getMessage());
        }
        if (c.version != Labels.VERSION || c.suite != Labels.SUITE) {
            throw new HandshakeException(
                    HandshakeException.Reason.UNSUPPORTED_VERSION, "version " + c.version + " suite " + c.suite);
        }
        TrustFile trusted = trust.find(c.keyId)
                .orElseThrow(() -> new HandshakeException(
                        HandshakeException.Reason.UNTRUSTED_SERVER, "no trust file for this server"));
        Set<Scope> scopes;
        try {
            scopes = Scope.fromMask(c.scopeMask);
        } catch (IllegalArgumentException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, e.getMessage());
        }
        if (c.proofRatePercent > 100) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, "proof rate > 100");
        }

        byte[] th1 = Digests.framed(Labels.TH1, context, c.unsigned());
        if (!Curves.verify(trusted.serverPublicKey(), Digests.framed(Labels.CHALLENGE_SIG, th1), c.signature)) {
            throw new HandshakeException(HandshakeException.Reason.BAD_SIGNATURE, "challenge signature invalid");
        }

        try {
            KeyPair eph = Curves.generateX25519(rnd);
            byte[] ephPub = Curves.rawPublic(eph.getPublic());
            byte[] nonceC = new byte[ServerChallenge.NONCE_LEN];
            rnd.nextBytes(nonceC);
            byte[] secretId = trusted.packSecret().id();
            byte[] ecdh = Curves.x25519(eph.getPrivate(), c.ephemeralKey);
            byte[] th2 = Digests.framed(
                    Labels.TH2, th1, new byte[] {(byte) Labels.VERSION}, secretId, ephPub, nonceC);
            SessionKeys keys = SessionKeys.derive(ecdh, trusted.packSecret().value(), c.nonce, nonceC, th2);
            return new ClientHandshake(
                    Collections.unmodifiableSet(scopes),
                    c.proofRatePercent,
                    secretId,
                    ephPub,
                    nonceC,
                    th2,
                    keys,
                    new ProofContext(keys.proof, c.nonce, c.proofRatePercent));
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, "key agreement failed", e);
        }
    }

    /** サーバーが報告を要求している範囲。 */
    public Set<Scope> requestedScopes() {
        return requestedScopes;
    }

    public int proofRatePercent() {
        return proofRatePercent;
    }

    /** 項目ごとの測定証明を作るためのコンテキスト(このセッション専用)。 */
    public ProofContext proofs() {
        return proofs;
    }

    public synchronized byte[] attest(Manifest manifest) throws HandshakeException {
        if (attested) {
            throw new HandshakeException(HandshakeException.Reason.REPLAY, "already attested");
        }
        attested = true;
        try {
            byte[] ct = Aead.seal(keys.c2s, 0, th2, manifest.encode());
            th3 = Digests.framed(Labels.TH3, th2, ct);
            return new ClientAttestation(Labels.VERSION, secretId, ephemeralPublic, nonceC, ct).encode();
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(HandshakeException.Reason.INTERNAL, "seal failed", e);
        } catch (WireException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, e.getMessage());
        }
    }

    public synchronized ServerVerdict readVerdict(byte[] verdictBytes) throws HandshakeException {
        if (th3 == null) {
            throw new HandshakeException(HandshakeException.Reason.INTERNAL, "attest() must be called first");
        }
        try {
            WireReader r = new WireReader(verdictBytes);
            int version = r.u8();
            if (version != Labels.VERSION) {
                throw new HandshakeException(HandshakeException.Reason.UNSUPPORTED_VERSION, "version " + version);
            }
            byte[] ct = r.blob(4096);
            r.requireEnd();
            return ServerVerdict.decode(Aead.open(keys.s2c, 0, th3, ct));
        } catch (WireException e) {
            throw new HandshakeException(HandshakeException.Reason.MALFORMED, e.getMessage());
        } catch (AEADBadTagException e) {
            throw new HandshakeException(HandshakeException.Reason.AUTH_FAILED, "verdict authentication failed");
        } catch (GeneralSecurityException e) {
            throw new HandshakeException(HandshakeException.Reason.INTERNAL, "open failed", e);
        }
    }
}
