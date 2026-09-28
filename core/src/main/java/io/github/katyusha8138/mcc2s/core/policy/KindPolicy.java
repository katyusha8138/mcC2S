package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.model.Entry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/** 項目種別ごと(Mod・リソースパックなど)の許可ルール。 */
public final class KindPolicy {
    private final MatchMode match;
    private final boolean allowBaseline;
    private final List<AllowEntry> allow;

    /**
     * @param allowBaseline サーバー自身の同種項目(サーバーに入っている Mod など)を許可するか
     * @throws IllegalArgumentException match の厳密さに対してホワイトリスト項目の指定が不足している場合
     *     (例: hash モードで sha256 の無い項目。意図せず広い許可になるのを防ぐ)
     */
    public KindPolicy(MatchMode match, boolean allowBaseline, List<AllowEntry> allow) {
        for (AllowEntry a : allow) {
            switch (match) {
                case HASH:
                    if (a.sha256().isEmpty()) {
                        throw new IllegalArgumentException(
                                "match=hash requires sha256 on every allow entry (id=" + a.id() + ")");
                    }
                    break;
                case ID_VERSION:
                    if (a.id() == null || a.version() == null) {
                        throw new IllegalArgumentException("match=id_version requires id and version on every allow entry");
                    }
                    break;
                case ID:
                    if (a.id() == null) {
                        throw new IllegalArgumentException("match=id requires id on every allow entry");
                    }
                    break;
                default:
                    throw new IllegalStateException();
            }
        }
        this.match = match;
        this.allowBaseline = allowBaseline;
        this.allow = Collections.unmodifiableList(new ArrayList<>(allow));
    }

    public static KindPolicy defaults() {
        return new KindPolicy(MatchMode.HASH, true, Collections.emptyList());
    }

    public MatchMode match() {
        return match;
    }

    public boolean allowBaseline() {
        return allowBaseline;
    }

    public List<AllowEntry> allow() {
        return allow;
    }

    /** {@code baseline} は同じ種別のサーバー側項目。 */
    public boolean allows(Entry e, List<Entry> baseline) {
        for (AllowEntry a : allow) {
            if (a.matches(e)) {
                return true;
            }
        }
        if (allowBaseline) {
            for (Entry b : baseline) {
                if (matchesBaseline(e, b)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean matchesBaseline(Entry e, Entry b) {
        switch (match) {
            case HASH:
                return e.sha256().equals(b.sha256());
            case ID_VERSION:
                return e.id().equals(b.id()) && e.version().equals(b.version());
            case ID:
                return e.id().equals(b.id());
            default:
                throw new IllegalStateException();
        }
    }

    /** サーバー側に同じ ID の項目があるか(ハッシュ不一致の診断用)。 */
    public Optional<Entry> baselineWithSameId(Entry e, List<Entry> baseline) {
        for (Entry b : baseline) {
            if (b.id().equals(e.id())) {
                return Optional.of(b);
            }
        }
        return Optional.empty();
    }
}
