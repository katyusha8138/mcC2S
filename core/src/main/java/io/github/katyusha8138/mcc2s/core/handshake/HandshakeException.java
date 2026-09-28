package io.github.katyusha8138.mcc2s.core.handshake;

/** ハンドシェイクの失敗。理由はサーバーログ用で、クライアントには詳細を返さない。 */
public final class HandshakeException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Reason {
        /** 構文エラー・長さ超過。 */
        MALFORMED,
        /** プロトコル版/暗号スイートが未対応(ダウングレード拒否)。 */
        UNSUPPORTED_VERSION,
        /** チャレンジのサーバー鍵がクライアントの信頼ファイルに無い。 */
        UNTRUSTED_SERVER,
        /** チャレンジ署名の検証失敗(改ざん・なりすまし・コンテキスト不一致)。 */
        BAD_SIGNATURE,
        /** サーバーが知らない pack_secret(信頼ファイルが古い・偽物)。 */
        UNKNOWN_SECRET,
        /** AEAD 認証失敗(pack_secret 不一致・改ざん・別セッションのリプレイ)。 */
        AUTH_FAILED,
        /** 1 つのハンドシェイクを 2 回使おうとした。 */
        REPLAY,
        /** 暗号ライブラリの内部エラー。 */
        INTERNAL
    }

    private final Reason reason;

    public HandshakeException(Reason reason, String message) {
        super(reason + ": " + message);
        this.reason = reason;
    }

    public HandshakeException(Reason reason, String message, Throwable cause) {
        super(reason + ": " + message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
