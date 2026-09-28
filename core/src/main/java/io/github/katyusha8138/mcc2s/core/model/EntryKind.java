package io.github.katyusha8138.mcc2s.core.model;

/** マニフェスト項目の種別。ワイヤー上のコードは固定(変更不可)。 */
public enum EntryKind {
    /** FML に Mod として登録された jar。 */
    MOD(1, Scope.MODS),
    /** `mods/` にあるが Mod として登録されない jar(mods.toml の無いライブラリ・隠し jar)。 */
    LIBRARY(2, Scope.MODS),
    RESOURCE_PACK(3, Scope.RESOURCE_PACKS),
    SHADER_PACK(4, Scope.SHADER_PACKS),
    /** `-javaagent` / `-agentpath` で読み込まれたエージェント。 */
    AGENT(5, Scope.JVM_AGENTS),
    /** 上記以外でゲームのコード源に加わっているもの(未登録のクラスパス jar など)。 */
    OTHER_CODE(6, Scope.JVM_AGENTS),
    /** mcC2S 自身のビルド。 */
    SELF(7, null);

    private final int code;
    private final Scope scope;

    EntryKind(int code, Scope scope) {
        this.code = code;
        this.scope = scope;
    }

    public int code() {
        return code;
    }

    /** この種別が属する検証範囲。SELF は常時必須なので null。 */
    public Scope scope() {
        return scope;
    }

    public static EntryKind fromCode(int code) {
        for (EntryKind k : values()) {
            if (k.code == code) {
                return k;
            }
        }
        throw new IllegalArgumentException("unknown entry kind: " + code);
    }
}
