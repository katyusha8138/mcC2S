package io.github.katyusha8138.mcc2s.core.model;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.core.wire.WireReader;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * クライアントが暗号化して送る構成の全体像。
 * 個人情報を避けるため、ファイルパス・ユーザー名・OS 情報は含めない(項目は ID・版・ハッシュのみ)。
 */
public final class Manifest {
    public static final int FORMAT_VERSION = 1;
    public static final int MAX_ENTRIES = 4096;
    /** 平文マニフェストの上限(DoS 対策)。 */
    public static final int MAX_ENCODED_BYTES = 2 * 1024 * 1024;

    private static final int MAX_ENV_CHARS = 64;

    private final String minecraftVersion;
    private final String loaderName;
    private final String loaderVersion;
    private final String mcC2SVersion;
    private final Set<Scope> reportedScopes;
    private final List<Entry> entries;

    public Manifest(
            String minecraftVersion,
            String loaderName,
            String loaderVersion,
            String mcC2SVersion,
            Set<Scope> reportedScopes,
            List<Entry> entries) {
        this.minecraftVersion = Entry.text(minecraftVersion, "minecraftVersion", MAX_ENV_CHARS);
        this.loaderName = Entry.text(loaderName, "loaderName", MAX_ENV_CHARS);
        this.loaderVersion = Entry.text(loaderVersion, "loaderVersion", MAX_ENV_CHARS);
        this.mcC2SVersion = Entry.text(mcC2SVersion, "mcC2SVersion", MAX_ENV_CHARS);
        this.reportedScopes = Collections.unmodifiableSet(
                reportedScopes.isEmpty() ? EnumSet.noneOf(Scope.class) : EnumSet.copyOf(reportedScopes));
        if (entries.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException("too many entries");
        }
        this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public String minecraftVersion() {
        return minecraftVersion;
    }

    public String loaderName() {
        return loaderName;
    }

    public String loaderVersion() {
        return loaderVersion;
    }

    public String mcC2SVersion() {
        return mcC2SVersion;
    }

    /** クライアントが「報告を完了した」と申告する範囲。要求範囲を満たさなければサーバーは拒否する。 */
    public Set<Scope> reportedScopes() {
        return reportedScopes;
    }

    public List<Entry> entries() {
        return entries;
    }

    public byte[] encode() {
        WireWriter w = new WireWriter();
        w.u8(FORMAT_VERSION);
        w.str(minecraftVersion, MAX_ENV_CHARS * 4);
        w.str(loaderName, MAX_ENV_CHARS * 4);
        w.str(loaderVersion, MAX_ENV_CHARS * 4);
        w.str(mcC2SVersion, MAX_ENV_CHARS * 4);
        w.u8(Scope.toMask(reportedScopes));
        w.u16(entries.size());
        for (Entry e : entries) {
            w.u8(e.kind().code());
            w.str(e.id(), Entry.MAX_ID_CHARS * 4);
            w.str(e.version(), Entry.MAX_VERSION_CHARS * 4);
            w.fixed(Digests.fromHex(e.sha256()), 32);
            byte[] proof = e.proof();
            if (proof == null) {
                w.u8(0);
            } else {
                w.u8(1);
                w.fixed(proof, Entry.PROOF_LEN);
            }
        }
        byte[] out = w.toByteArray();
        if (out.length > MAX_ENCODED_BYTES) {
            throw new WireException("manifest too large");
        }
        return out;
    }

    /** 未信頼入力の厳格なデコード。あらゆる不正は {@link WireException} になる。 */
    public static Manifest decode(byte[] data) {
        if (data.length > MAX_ENCODED_BYTES) {
            throw new WireException("manifest too large");
        }
        try {
            WireReader r = new WireReader(data);
            int ver = r.u8();
            if (ver != FORMAT_VERSION) {
                throw new WireException("unsupported manifest version " + ver);
            }
            String mc = r.str(MAX_ENV_CHARS * 4);
            String loader = r.str(MAX_ENV_CHARS * 4);
            String loaderVer = r.str(MAX_ENV_CHARS * 4);
            String self = r.str(MAX_ENV_CHARS * 4);
            Set<Scope> scopes = Scope.fromMask(r.u8());
            int count = r.u16();
            if (count > MAX_ENTRIES) {
                throw new WireException("too many entries");
            }
            List<Entry> entries = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                EntryKind kind = EntryKind.fromCode(r.u8());
                String id = r.str(Entry.MAX_ID_CHARS * 4);
                String version = r.str(Entry.MAX_VERSION_CHARS * 4);
                String sha = Digests.hex(r.fixed(32));
                int hasProof = r.u8();
                byte[] proof;
                if (hasProof == 0) {
                    proof = null;
                } else if (hasProof == 1) {
                    proof = r.fixed(Entry.PROOF_LEN);
                } else {
                    throw new WireException("bad proof flag");
                }
                entries.add(new Entry(kind, id, version, sha, proof));
            }
            r.requireEnd();
            return new Manifest(mc, loader, loaderVer, self, scopes, entries);
        } catch (IllegalArgumentException e) {
            // 種別・範囲・文字列検証の失敗はすべてワイヤーエラーとして扱う
            throw new WireException("invalid manifest: " + e.getMessage());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Manifest)) {
            return false;
        }
        Manifest m = (Manifest) o;
        return minecraftVersion.equals(m.minecraftVersion)
                && loaderName.equals(m.loaderName)
                && loaderVersion.equals(m.loaderVersion)
                && mcC2SVersion.equals(m.mcC2SVersion)
                && reportedScopes.equals(m.reportedScopes)
                && entries.equals(m.entries);
    }

    @Override
    public int hashCode() {
        return Objects.hash(minecraftVersion, loaderName, loaderVersion, mcC2SVersion, reportedScopes, entries);
    }
}
