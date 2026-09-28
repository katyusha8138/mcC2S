package io.github.katyusha8138.mcc2s.core.model;

import java.util.EnumSet;
import java.util.Set;

/** サーバーがクライアントに報告を要求する検証範囲。mcC2S 自身(SELF)は常に必須で、ここには含めない。 */
public enum Scope {
    MODS(1),
    RESOURCE_PACKS(2),
    SHADER_PACKS(4),
    JVM_AGENTS(8);

    private final int bit;

    Scope(int bit) {
        this.bit = bit;
    }

    public int bit() {
        return bit;
    }

    public static int toMask(Set<Scope> scopes) {
        int mask = 0;
        for (Scope s : scopes) {
            mask |= s.bit;
        }
        return mask;
    }

    /** 未知のビットが立っていれば例外(前方互換の暗黙受理を避ける)。 */
    public static EnumSet<Scope> fromMask(int mask) {
        EnumSet<Scope> out = EnumSet.noneOf(Scope.class);
        int rest = mask;
        for (Scope s : values()) {
            if ((mask & s.bit) != 0) {
                out.add(s);
                rest &= ~s.bit;
            }
        }
        if (rest != 0) {
            throw new IllegalArgumentException("unknown scope bits: " + rest);
        }
        return out;
    }
}
