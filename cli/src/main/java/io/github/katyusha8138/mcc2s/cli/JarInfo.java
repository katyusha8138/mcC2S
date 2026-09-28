// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.cli;

import com.electronwill.nightconfig.core.UnmodifiableConfig;
import com.electronwill.nightconfig.toml.TomlParser;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Mod jar から Mod ID とバージョンを読む(許可リストの id / version の下書き用)。読めなければ空を返す。 */
final class JarInfo {
    record Info(String modId, String version) {}

    private JarInfo() {}

    static Optional<Info> read(Path jar) {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            for (String name : new String[] {"META-INF/neoforge.mods.toml", "META-INF/mods.toml"}) {
                ZipEntry e = zip.getEntry(name);
                if (e == null) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(e)) {
                    UnmodifiableConfig root = new TomlParser().parse(in);
                    Object mods = root.get("mods");
                    if (mods instanceof List && !((List<?>) mods).isEmpty() && ((List<?>) mods).get(0) instanceof UnmodifiableConfig) {
                        UnmodifiableConfig first = (UnmodifiableConfig) ((List<?>) mods).get(0);
                        String id = first.get("modId");
                        String version = first.get("version");
                        if (id != null) {
                            return Optional.of(new Info(id, resolveVersion(zip, version)));
                        }
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            // 壊れた jar・想定外の形式は「読めなかった」として扱う
        }
        return Optional.empty();
    }

    /** `${file.jarVersion}` のようなプレースホルダは、jar の MANIFEST の Implementation-Version で置き換える。 */
    private static String resolveVersion(ZipFile zip, String version) throws IOException {
        if (version != null && !version.contains("${")) {
            return version;
        }
        ZipEntry mf = zip.getEntry("META-INF/MANIFEST.MF");
        if (mf != null) {
            try (InputStream in = zip.getInputStream(mf)) {
                String v = new Manifest(in).getMainAttributes().getValue("Implementation-Version");
                if (v != null) {
                    return v;
                }
            }
        }
        return "";
    }
}
