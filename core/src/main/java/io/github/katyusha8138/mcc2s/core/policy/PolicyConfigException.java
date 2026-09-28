package io.github.katyusha8138.mcc2s.core.policy;

/** ポリシー設定ファイルの誤り。誤設定で意図せず許可が広がらないよう、曖昧な設定は起動時に拒否する。 */
public final class PolicyConfigException extends Exception {
    private static final long serialVersionUID = 1L;

    public PolicyConfigException(String message) {
        super(message);
    }

    public PolicyConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
