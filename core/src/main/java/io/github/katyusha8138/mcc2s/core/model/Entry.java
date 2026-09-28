// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.model;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.util.Arrays;
import java.util.Objects;

/**
 * クライアントが報告する 1 項目。
 *
 * @param id リソース識別子(Mod ID、パック名、jar ファイル名など。パスは含めない)
 * @param version バージョン文字列(不明なら空)
 * @param sha256 内容の SHA-256(小文字 16 進 64 文字)
 * @param proof セッション束縛の証明(HMAC)。無ければ null
 */
public record Entry(EntryKind kind, String id, String version, String sha256, byte[] proof) {
    public static final int MAX_ID_CHARS = 256;
    public static final int MAX_VERSION_CHARS = 128;
    public static final int PROOF_LEN = 32;

    public Entry {
        Objects.requireNonNull(kind, "kind");
        id = text(id, "id", MAX_ID_CHARS);
        version = version == null ? "" : text(version, "version", MAX_VERSION_CHARS);
        if (!Digests.isSha256Hex(sha256)) {
            throw new IllegalArgumentException("sha256 must be 64 lowercase hex chars");
        }
        if (proof != null) {
            if (proof.length != PROOF_LEN) {
                throw new IllegalArgumentException("proof must be " + PROOF_LEN + " bytes");
            }
            proof = proof.clone();
        }
    }

    public Entry(EntryKind kind, String id, String version, String sha256) {
        this(kind, id, version, sha256, null);
    }

    @Override
    public byte[] proof() {
        return proof == null ? null : proof.clone();
    }

    public Entry withProof(byte[] newProof) {
        return new Entry(kind, id, version, sha256, newProof);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Entry)) {
            return false;
        }
        Entry e = (Entry) o;
        return kind == e.kind
                && id.equals(e.id)
                && version.equals(e.version)
                && sha256.equals(e.sha256)
                && Arrays.equals(proof, e.proof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, id, version, sha256) * 31 + Arrays.hashCode(proof);
    }

    @Override
    public String toString() {
        return kind + "[" + id + (version.isEmpty() ? "" : "@" + version) + " sha256=" + sha256 + "]";
    }

    /** 制御文字(ログ偽装・端末エスケープの温床)を含む文字列を拒否する。 */
    static String text(String s, String field, int maxChars) {
        Objects.requireNonNull(s, field);
        if (s.length() > maxChars) {
            throw new IllegalArgumentException(field + " too long");
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || c == ' ' || c == ' ') {
                throw new IllegalArgumentException(field + " contains control characters");
            }
        }
        return s;
    }
}
