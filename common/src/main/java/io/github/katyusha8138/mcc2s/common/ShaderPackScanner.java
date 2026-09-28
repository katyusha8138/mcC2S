// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * 有効なシェーダーパックを報告する。Iris / Oculus の設定ファイル({@code config/iris.properties} など)から、
 * シェーダーが有効なときの {@code shaderPack} を読む。{@code shaderpacks/} にあるだけで使われていないものは対象外。
 */
public final class ShaderPackScanner {
    private static final String[] CONFIGS = {"config/iris.properties", "config/oculus.properties"};

    private ShaderPackScanner() {}

    public static List<EntrySeed> scan(Path gameDir, Hasher hasher) {
        List<EntrySeed> out = new ArrayList<>();
        Path packsDir = gameDir.resolve("shaderpacks").toAbsolutePath().normalize();
        for (String cfg : CONFIGS) {
            Path file = gameDir.resolve(cfg);
            if (!Files.isRegularFile(file)) {
                continue;
            }
            Properties props = new Properties();
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            } catch (IOException | IllegalArgumentException e) {
                out.add(new EntrySeed(EntryKind.SHADER_PACK, "unreadable:" + file.getFileName(), "", ModScanner.UNREADABLE_SHA, null));
                continue;
            }
            String name = props.getProperty("shaderPack", "").trim();
            boolean enabled = !"false".equalsIgnoreCase(props.getProperty("enableShaders", "true").trim());
            if (!enabled || name.isEmpty() || name.equals("(internal)")) {
                continue;
            }
            Path pack = packsDir.resolve(name).normalize();
            String sha = ModScanner.UNREADABLE_SHA;
            Path proofFile = null;
            if (pack.startsWith(packsDir)) {
                try {
                    sha = hasher.sha256(pack);
                    proofFile = Files.isRegularFile(pack) ? pack : null;
                } catch (IOException e) {
                    // 見つからない/読めない: ゼロのハッシュで報告(隠さない)
                }
            }
            out.add(new EntrySeed(EntryKind.SHADER_PACK, name, "", sha, proofFile));
        }
        return out;
    }
}
