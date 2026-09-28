// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@code mods/} フォルダの実ファイルと、ローダーが読み込んだ Mod の差分を取る。
 * <ul>
 *   <li>ローダーが Mod として登録した jar → {@code MOD}(ID・バージョン付き)</li>
 *   <li>{@code mods/} にあるが Mod として登録されない jar(ライブラリ・隠し jar)→ {@code LIBRARY}</li>
 * </ul>
 * FML は {@code mods/} 直下の {@code *.jar}(大文字小文字を区別しない)だけを走査するので、それに合わせる。
 * 読めないファイルは「無かったこと」にせず、ゼロのハッシュで報告する(=許可されないので隠せない)。
 */
public final class ModScanner {
    /** 読み取りに失敗したファイルのハッシュ。どのホワイトリストにも載らない。 */
    public static final String UNREADABLE_SHA = "0".repeat(64);

    private ModScanner() {}

    /**
     * @param platformModIds {@code minecraft} / {@code neoforge} など、クライアントとサーバーで
     *     ファイルが異なるため比較対象にしないプラットフォーム Mod の ID
     */
    public static List<EntrySeed> scan(Path modsDir, List<LoadedMod> loaded, Set<String> platformModIds, Hasher cache)
            throws IOException {
        Map<Path, LoadedMod> loadedByPath = new HashMap<>();
        for (LoadedMod m : loaded) {
            loadedByPath.put(canonical(m.path()), m);
        }

        List<EntrySeed> out = new ArrayList<>();
        Set<Path> seen = new HashSet<>();

        if (Files.isDirectory(modsDir)) {
            List<Path> jars;
            try (Stream<Path> s = Files.list(modsDir)) {
                jars = s.filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar"))
                        .filter(Files::isRegularFile)
                        .sorted(Comparator.comparing(p -> p.getFileName().toString().toLowerCase(Locale.ROOT)))
                        .collect(Collectors.toList());
            }
            for (Path jar : jars) {
                Path c = canonical(jar);
                if (!seen.add(c)) {
                    continue;
                }
                LoadedMod mod = loadedByPath.get(c);
                String sha = hashOrUnreadable(jar, cache);
                if (mod == null) {
                    out.add(new EntrySeed(EntryKind.LIBRARY, jar.getFileName().toString(), "", sha, jar));
                } else {
                    out.add(modSeed(mod, platformModIds, sha, jar));
                }
            }
        }

        // mods/ の外から読み込まれた Mod(--fml.mods 等)。プラットフォーム Mod は比較しない。
        for (LoadedMod mod : loaded) {
            Path c = canonical(mod.path());
            if (seen.contains(c) || platformModIds.containsAll(mod.modIds())) {
                continue;
            }
            if (!mod.path().getFileSystem().equals(FileSystems.getDefault()) || !Files.exists(c)) {
                continue; // JarJar の内側など、親ファイルのハッシュに含まれるもの
            }
            seen.add(c);
            out.add(modSeed(mod, platformModIds, hashOrUnreadable(c, cache), c));
        }

        out.sort(Comparator.comparing((EntrySeed e) -> e.kind().code())
                .thenComparing(EntrySeed::id)
                .thenComparing(EntrySeed::sha256));
        return out;
    }

    private static EntrySeed modSeed(LoadedMod mod, Set<String> platform, String sha, Path file) {
        String id = mod.modIds().stream().filter(i -> !platform.contains(i)).findFirst()
                .orElse(mod.modIds().isEmpty() ? file.getFileName().toString() : mod.modIds().get(0));
        return new EntrySeed(EntryKind.MOD, id, mod.version(), sha, Files.isRegularFile(file) ? file : null);
    }

    private static String hashOrUnreadable(Path p, Hasher cache) {
        try {
            return cache.sha256(p);
        } catch (IOException e) {
            return UNREADABLE_SHA;
        }
    }

    private static Path canonical(Path p) {
        try {
            return p.toRealPath();
        } catch (IOException e) {
            return p.toAbsolutePath().normalize();
        }
    }
}
