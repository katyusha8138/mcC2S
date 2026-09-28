package io.github.katyusha8138.mcc2s.core.policy;

/** 許可判定の厳密さ。 */
public enum MatchMode {
    /** jar/パックの SHA-256 が一致すること(既定。バイト単位で同一のものだけ許可)。 */
    HASH,
    /** ID とバージョンが一致すること。 */
    ID_VERSION,
    /** ID のみ一致すること。 */
    ID
}
