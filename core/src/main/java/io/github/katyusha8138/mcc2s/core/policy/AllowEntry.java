package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * ホワイトリスト 1 件。指定されたフィールド(id / version / sha256)が「すべて」一致した項目だけが許可される。
 * 未指定のフィールドは条件にならない。
 */
public final class AllowEntry {
    private final String id;
    private final String version;
    private final Set<String> sha256;
    private final String note;

    public AllowEntry(String id, String version, Set<String> sha256, String note) {
        this.id = id == null || id.isEmpty() ? null : id;
        this.version = version == null || version.isEmpty() ? null : version;
        Set<String> hashes = new LinkedHashSet<>();
        if (sha256 != null) {
            for (String h : sha256) {
                String lower = h.toLowerCase(java.util.Locale.ROOT);
                if (!Digests.isSha256Hex(lower)) {
                    throw new IllegalArgumentException("invalid sha256: " + h);
                }
                hashes.add(lower);
            }
        }
        this.sha256 = Collections.unmodifiableSet(hashes);
        this.note = note == null ? "" : note;
        if (this.id == null && this.version == null && this.sha256.isEmpty()) {
            throw new IllegalArgumentException("allow entry must specify at least one of id / version / sha256");
        }
    }

    public String id() {
        return id;
    }

    public String version() {
        return version;
    }

    public Set<String> sha256() {
        return sha256;
    }

    public String note() {
        return note;
    }

    public boolean matches(Entry e) {
        return (id == null || id.equals(e.id()))
                && (version == null || version.equals(e.version()))
                && (sha256.isEmpty() || sha256.contains(e.sha256()));
    }
}
