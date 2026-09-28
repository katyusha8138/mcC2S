// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ファイル/フォルダの SHA-256 を計算し、(パス, サイズ, 更新時刻) が変わらない限り再計算しない。
 * 数百個の Mod jar を毎回ハッシュしないためのキャッシュ(メモリ内のみ)。
 * フォルダはツリーハッシュ({@link Digests#treeHashHex})でキャッシュしない。
 */
public final class HashCache implements Hasher {
    private static final class Value {
        final long size;
        final long modifiedMillis;
        final String sha;

        Value(long size, long modifiedMillis, String sha) {
            this.size = size;
            this.modifiedMillis = modifiedMillis;
            this.sha = sha;
        }
    }

    private final ConcurrentHashMap<Path, Value> cache = new ConcurrentHashMap<>();

    @Override
    public String sha256(Path path) throws IOException {
        Path p = path.toAbsolutePath().normalize();
        BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class);
        if (attrs.isDirectory()) {
            return Digests.treeHashHex(p);
        }
        long size = attrs.size();
        long modified = attrs.lastModifiedTime().toMillis();
        Value v = cache.get(p);
        if (v != null && v.size == size && v.modifiedMillis == modified) {
            return v.sha;
        }
        String sha = Digests.hex(Digests.sha256(p));
        cache.put(p, new Value(size, modified, sha));
        return sha;
    }
}
