// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.ReferenceResolver;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * サーバーが持っている「参照ファイル」(SHA-256 → ファイル)。測定証明の検証に使う。
 * 対象は、サーバー自身の Mod・mcC2S 本体・運営者が {@code reference/} に置いた jar/zip。
 * 索引を作った後にファイルが変更されていたら(サイズ/更新時刻の不一致)、誤検知を避けるため参照なしとして扱う。
 */
public final class ReferenceIndex implements ReferenceResolver {
    private static final class Ref {
        final Path path;
        final long size;
        final long modifiedMillis;

        Ref(Path path, long size, long modifiedMillis) {
            this.path = path;
            this.size = size;
            this.modifiedMillis = modifiedMillis;
        }
    }

    private final Map<String, Ref> bySha;

    private ReferenceIndex(Map<String, Ref> bySha) {
        this.bySha = bySha;
    }

    public static ReferenceIndex empty() {
        return new ReferenceIndex(new HashMap<>());
    }

    /**
     * @param own サーバー自身の項目(実ファイルを持つもののみ索引に入る)
     * @param referenceDir 運営者が置く参照ファイルのフォルダ(無くてもよい)
     */
    public static ReferenceIndex build(List<EntrySeed> own, Path referenceDir, Hasher cache, Log log) {
        Map<String, Ref> map = new HashMap<>();
        for (EntrySeed s : own) {
            if (s.file() != null) {
                add(map, s.sha256(), s.file());
            }
        }
        if (referenceDir != null && Files.isDirectory(referenceDir)) {
            List<Path> files;
            try (Stream<Path> st = Files.list(referenceDir)) {
                files = st.filter(Files::isRegularFile)
                        .filter(p -> {
                            String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
                            return n.endsWith(".jar") || n.endsWith(".zip");
                        })
                        .collect(Collectors.toList());
            } catch (IOException e) {
                log.error("could not list " + referenceDir, e);
                files = List.of();
            }
            for (Path p : files) {
                try {
                    add(map, cache.sha256(p), p);
                } catch (IOException e) {
                    log.warn("could not hash reference file " + p + ": " + e.getMessage());
                }
            }
        }
        return new ReferenceIndex(map);
    }

    private static void add(Map<String, Ref> map, String sha, Path file) {
        try {
            map.putIfAbsent(sha, new Ref(file, Files.size(file), Files.getLastModifiedTime(file).toMillis()));
        } catch (IOException e) {
            // 読めないものは索引に入れない
        }
    }

    public int size() {
        return bySha.size();
    }

    @Override
    public Optional<InputStream> open(EntryKind kind, String sha256Hex) throws IOException {
        Ref r = bySha.get(sha256Hex);
        if (r == null) {
            return Optional.empty();
        }
        if (Files.size(r.path) != r.size || Files.getLastModifiedTime(r.path).toMillis() != r.modifiedMillis) {
            return Optional.empty(); // 索引作成後に変更された
        }
        return Optional.of(Files.newInputStream(r.path));
    }
}
