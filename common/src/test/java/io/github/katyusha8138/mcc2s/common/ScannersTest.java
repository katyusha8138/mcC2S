// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScannersTest {
    @TempDir Path tmp;

    private static String sha(String s) {
        return Digests.hex(Digests.sha256(s.getBytes(StandardCharsets.UTF_8)));
    }

    // ---- HashCache ----

    @Test
    void hashCacheReturnsCorrectHashesAndNoticesChanges() throws Exception {
        Path f = tmp.resolve("a.jar");
        Files.writeString(f, "one");
        HashCache c = new HashCache();
        assertEquals(sha("one"), c.sha256(f));
        assertEquals(sha("one"), c.sha256(f));

        Files.writeString(f, "twelve"); // サイズが変わる
        assertEquals(sha("twelve"), c.sha256(f));

        Files.writeString(f, "SAMES6"); // 同サイズ
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5000));
        assertEquals(sha("SAMES6"), c.sha256(f));
    }

    @Test
    void hashCacheHandlesDirectoriesAsTrees() throws Exception {
        Path d = Files.createDirectories(tmp.resolve("pack"));
        Files.writeString(d.resolve("pack.mcmeta"), "{}");
        HashCache c = new HashCache();
        String before = c.sha256(d);
        Files.writeString(d.resolve("pack.mcmeta"), "{ }");
        assertNotEquals(before, c.sha256(d));
    }

    // ---- ModScanner ----

    private Path mods() throws IOException {
        return Files.createDirectories(tmp.resolve("mods"));
    }

    private Path jar(Path dir, String name, String content) throws IOException {
        Path p = dir.resolve(name);
        Files.writeString(p, content);
        return p;
    }

    @Test
    void registeredJarsAreModsAndOthersAreLibraries() throws Exception {
        Path mods = mods();
        Path create = jar(mods, "create-6.0.jar", "create");
        jar(mods, "hidden-loader.jar", "cheat");
        List<LoadedMod> loaded = List.of(new LoadedMod(create, List.of("create", "flywheel"), "6.0"));

        List<EntrySeed> seeds = ModScanner.scan(mods, loaded, Set.of("minecraft", "neoforge"), new HashCache());
        assertEquals(2, seeds.size());
        EntrySeed mod = seeds.stream().filter(s -> s.kind() == EntryKind.MOD).findFirst().orElseThrow();
        assertEquals("create", mod.id());
        assertEquals("6.0", mod.version());
        assertEquals(sha("create"), mod.sha256());
        EntrySeed lib = seeds.stream().filter(s -> s.kind() == EntryKind.LIBRARY).findFirst().orElseThrow();
        assertEquals("hidden-loader.jar", lib.id());
        assertEquals(sha("cheat"), lib.sha256());
    }

    @Test
    void scannerMirrorsFmlRules() throws Exception {
        Path mods = mods();
        jar(mods, "UPPER.JAR", "upper"); // 大文字の拡張子も FML は読み込む
        jar(mods, "readme.txt", "not a jar");
        Files.createDirectories(mods.resolve("sub.jar")); // ディレクトリは対象外
        jar(Files.createDirectories(mods.resolve("nested")), "deep.jar", "deep"); // 下位フォルダは FML も読まない

        List<EntrySeed> seeds = ModScanner.scan(mods, List.of(), Set.of(), new HashCache());
        assertEquals(1, seeds.size());
        assertEquals("UPPER.JAR", seeds.get(0).id());
    }

    @Test
    void platformModsOutsideModsDirAreNotCompared() throws Exception {
        Path libs = Files.createDirectories(tmp.resolve("libraries"));
        Path neo = jar(libs, "neoforge-client.jar", "neoforge client patched");
        Path external = jar(libs, "extra.jar", "extra mod loaded via --fml.mods");
        List<LoadedMod> loaded = List.of(
                new LoadedMod(neo, List.of("neoforge", "minecraft"), "21.1.0"),
                new LoadedMod(external, List.of("extra"), "1.0"));

        List<EntrySeed> seeds = ModScanner.scan(mods(), loaded, Set.of("minecraft", "neoforge"), new HashCache());
        assertEquals(1, seeds.size());
        assertEquals("extra", seeds.get(0).id()); // mods/ の外から読み込まれた Mod も報告される
    }

    @Test
    void unreadableFilesAreReportedNotHidden() throws Exception {
        Path mods = mods();
        Path broken = jar(mods, "broken.jar", "x");
        Hasher failing = path -> {
            throw new IOException("locked");
        };
        List<EntrySeed> seeds = ModScanner.scan(mods, List.of(), Set.of(), failing);
        assertEquals(1, seeds.size());
        assertEquals(ModScanner.UNREADABLE_SHA, seeds.get(0).sha256());
        assertTrue(Files.exists(broken));
    }

    @Test
    void outputIsDeterministic() throws Exception {
        Path mods = mods();
        for (String n : new String[] {"b.jar", "a.jar", "c.jar"}) {
            jar(mods, n, n);
        }
        List<EntrySeed> one = ModScanner.scan(mods, List.of(), Set.of(), new HashCache());
        List<EntrySeed> two = ModScanner.scan(mods, List.of(), Set.of(), new HashCache());
        assertEquals(one, two);
        assertEquals(List.of("a.jar", "b.jar", "c.jar"), one.stream().map(EntrySeed::id).toList());
    }

    // ---- AgentScanner ----

    @Test
    void javaAgentsAreHashedAndOptionsStripped() throws Exception {
        Path agent = jar(tmp, "agent.jar", "agent bytes");
        List<EntrySeed> seeds = AgentScanner.scan(
                List.of("-Xmx4G", "-javaagent:" + agent + "=debug=true", "-Dfoo=bar"), Map.of(), tmp, new HashCache());
        assertEquals(1, seeds.size());
        assertEquals(EntryKind.AGENT, seeds.get(0).kind());
        assertEquals("agent.jar", seeds.get(0).id());
        assertEquals(sha("agent bytes"), seeds.get(0).sha256());
    }

    @Test
    void relativeAgentPathsResolveAgainstTheWorkingDirectory() throws Exception {
        jar(tmp, "rel.jar", "rel bytes");
        List<EntrySeed> seeds = AgentScanner.scan(List.of("-javaagent:rel.jar"), Map.of(), tmp, new HashCache());
        assertEquals(sha("rel bytes"), seeds.get(0).sha256());
    }

    @Test
    void agentPathAgentLibAndBootClasspathAreCovered() throws Exception {
        Path lib = jar(tmp, "native.so", "native");
        Path boot = jar(tmp, "boot.jar", "boot");
        List<EntrySeed> seeds = AgentScanner.scan(
                List.of("-agentpath:" + lib, "-agentlib:jdwp=transport=dt_socket", "-Xbootclasspath/a:" + boot), Map.of(), tmp, new HashCache());
        assertEquals(3, seeds.size());
        assertEquals("native.so", seeds.get(0).id());
        assertEquals("agentlib:jdwp", seeds.get(1).id());
        assertNull(seeds.get(1).file());
        assertEquals(EntryKind.OTHER_CODE, seeds.get(2).kind());
        assertEquals(sha("boot"), seeds.get(2).sha256());
    }

    @Test
    void agentsInjectedThroughEnvironmentVariablesAreDetected() throws Exception {
        Path agent = jar(tmp, "env-agent.jar", "env agent");
        List<EntrySeed> seeds = AgentScanner.scan(
                List.of(), Map.of("JAVA_TOOL_OPTIONS", "-Dx=1 -javaagent:" + agent, "_JAVA_OPTIONS", "-javaagent:" + agent), tmp, new HashCache());
        assertEquals(1, seeds.size(), "same agent through two variables is reported once");
        assertEquals("env-agent.jar", seeds.get(0).id());
    }

    @Test
    void missingAgentFileStillProducesAnEntry() {
        List<EntrySeed> seeds = AgentScanner.scan(List.of("-javaagent:/nonexistent/x.jar"), Map.of(), tmp, new HashCache());
        assertEquals(1, seeds.size());
        assertEquals(ModScanner.UNREADABLE_SHA, seeds.get(0).sha256());
    }

    @Test
    void ordinaryJvmFlagsAreNotReported() {
        List<EntrySeed> seeds = AgentScanner.scan(
                List.of("-Xmx4G", "-XX:+UseG1GC", "-Dfile.encoding=UTF-8", "--add-modules=ALL-MODULE-PATH"), Map.of(), tmp, new HashCache());
        assertTrue(seeds.isEmpty());
        assertFalse(seeds.iterator().hasNext());
    }

    // ---- Sanitize ----

    @Test
    void sanitizeReplacesControlCharactersAndTruncates() {
        assertEquals("a?b?c", Sanitize.text("a\nb\u001bc", 100));
        assertEquals("abc", Sanitize.text("abcdef", 3));
        assertEquals("日本語.jar", Sanitize.text("日本語.jar", 100));
    }
}
