// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** ビッグエンディアンの単純な長さ付きバイナリ書き込み。すべてのフィールドに上限を課す。 */
public final class WireWriter {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public WireWriter u8(int v) {
        if (v < 0 || v > 0xFF) {
            throw new WireException("u8 out of range: " + v);
        }
        out.write(v);
        return this;
    }

    public WireWriter u16(int v) {
        if (v < 0 || v > 0xFFFF) {
            throw new WireException("u16 out of range: " + v);
        }
        out.write(v >>> 8);
        out.write(v);
        return this;
    }

    public WireWriter u32(long v) {
        if (v < 0 || v > 0xFFFFFFFFL) {
            throw new WireException("u32 out of range: " + v);
        }
        out.write((int) (v >>> 24));
        out.write((int) (v >>> 16));
        out.write((int) (v >>> 8));
        out.write((int) v);
        return this;
    }

    /** 長さ接頭辞なしでそのまま書く。 */
    public WireWriter raw(byte[] b) {
        out.write(b, 0, b.length);
        return this;
    }

    /** 長さが厳密に {@code len} のフィールド。 */
    public WireWriter fixed(byte[] b, int len) {
        if (b == null || b.length != len) {
            throw new WireException("fixed field must be " + len + " bytes");
        }
        return raw(b);
    }

    /** u32 長接頭辞付きバイト列。 */
    public WireWriter blob(byte[] b, int max) {
        if (b.length > max) {
            throw new WireException("blob too large: " + b.length + " > " + max);
        }
        u32(b.length);
        return raw(b);
    }

    /** u16 長接頭辞付き UTF-8 文字列(長さはバイト数で制限)。 */
    public WireWriter str(String s, int maxBytes) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (b.length > maxBytes || b.length > 0xFFFF) {
            throw new WireException("string too long: " + b.length + " > " + maxBytes);
        }
        u16(b.length);
        return raw(b);
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }
}
