package io.github.katyusha8138.mcc2s.core.policy;

/** 違反の種類。{@link #code()} はプレイヤーに見せる参照番号として使う。 */
public enum ViolationCode {
    /** ホワイトリストにもサーバー側にも無い項目。 */
    NOT_ALLOWED(1),
    /** サーバー側に同じ ID があるが、内容(ハッシュ)が違う。 */
    HASH_MISMATCH(2),
    /** 要求された検証範囲をクライアントが報告しなかった。 */
    SCOPE_MISSING(3),
    /** mcC2S 本体の項目が無い。 */
    SELF_MISSING(4),
    /** mcC2S 本体が公式ビルドではない(改造・偽物)。 */
    SELF_UNOFFICIAL(5),
    /** mcC2S 本体の項目が複数ある。 */
    DUPLICATE_SELF(6),
    /** 必須の測定証明が付いていない。 */
    PROOF_MISSING(7),
    /** 測定証明が一致しない(報告したハッシュのファイルを実際には持っていない)。 */
    PROOF_INVALID(8),
    /** 測定証明が必須だがサーバーに参照ファイルが無く検証できない(require_reference 有効時)。 */
    PROOF_UNVERIFIABLE(9);

    private final int code;

    ViolationCode(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }
}
