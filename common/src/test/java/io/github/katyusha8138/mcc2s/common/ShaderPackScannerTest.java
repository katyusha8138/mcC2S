// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ShaderPackScannerTest {
    @TempDir Path game;

    private void config(String file, String content) throws Exception {
        Files.createDirectories(game.resolve("config"));
        Files.writeString(game.resolve("config").resolve(file), content);
    }

    private Path pack(String name, String content) throws Exception {
        Files.createDirectories(game.resolve("shaderpacks"));
        Path p = game.resolve("shaderpacks").resolve(name);
        Files.writeString(p, content);
        return p;
    }

    private static String sha(String s) {
        return Digests.hex(Digests.sha256(s.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void activeShaderPackIsReported() throws Exception {
        pack("Complementary.zip", "shader bytes");
        pack("Unused.zip", "unused");
        config("iris.properties", "enableShaders=true\nshaderPack=Complementary.zip\n");
        List<EntrySeed> seeds = ShaderPackScanner.scan(game, new HashCache());
        assertEquals(1, seeds.size());
        assertEquals(EntryKind.SHADER_PACK, seeds.get(0).kind());
        assertEquals("Complementary.zip", seeds.get(0).id());
        assertEquals(sha("shader bytes"), seeds.get(0).sha256());
    }

    @Test
    void disabledInternalOrMissingConfigReportsNothing() throws Exception {
        pack("A.zip", "a");
        assertTrue(ShaderPackScanner.scan(game, new HashCache()).isEmpty()); // 設定なし
        config("iris.properties", "enableShaders=false\nshaderPack=A.zip\n");
        assertTrue(ShaderPackScanner.scan(game, new HashCache()).isEmpty()); // 無効
        config("iris.properties", "enableShaders=true\nshaderPack=(internal)\n");
        assertTrue(ShaderPackScanner.scan(game, new HashCache()).isEmpty()); // 内蔵
        config("iris.properties", "shaderPack=\n");
        assertTrue(ShaderPackScanner.scan(game, new HashCache()).isEmpty());
    }

    @Test
    void shaderPackWithoutEnableFlagCountsAsEnabled() throws Exception {
        pack("A.zip", "a");
        config("oculus.properties", "shaderPack=A.zip\n");
        assertEquals(1, ShaderPackScanner.scan(game, new HashCache()).size());
    }

    @Test
    void missingOrEscapingPackIsReportedAsUnreadableNotHidden() throws Exception {
        config("iris.properties", "shaderPack=gone.zip\n");
        List<EntrySeed> seeds = ShaderPackScanner.scan(game, new HashCache());
        assertEquals(ModScanner.UNREADABLE_SHA, seeds.get(0).sha256());

        Files.writeString(game.resolve("outside.zip"), "x");
        config("iris.properties", "shaderPack=../outside.zip\n");
        seeds = ShaderPackScanner.scan(game, new HashCache());
        assertEquals(ModScanner.UNREADABLE_SHA, seeds.get(0).sha256()); // shaderpacks/ の外は辿らない
    }

    @Test
    void folderShaderPacksUseTreeHash() throws Exception {
        Path dir = Files.createDirectories(game.resolve("shaderpacks/Folder"));
        Files.writeString(dir.resolve("shaders.properties"), "x");
        config("iris.properties", "shaderPack=Folder\n");
        List<EntrySeed> seeds = ShaderPackScanner.scan(game, new HashCache());
        assertEquals(1, seeds.size());
        assertTrue(seeds.get(0).file() == null, "folders have no single file to prove");
    }
}
