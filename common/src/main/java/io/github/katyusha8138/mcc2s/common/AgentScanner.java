// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JVM 引数から、ゲームのコードに介入し得るものだけを取り出す(全引数は報告しない)。
 * <ul>
 *   <li>{@code -javaagent:} / {@code -agentpath:} → {@code AGENT}(エージェント jar / ネイティブライブラリのハッシュ)</li>
 *   <li>{@code -agentlib:} → {@code AGENT}(ライブラリ名のハッシュ。実体は JVM のパスから解決されるため)</li>
 *   <li>{@code -Xbootclasspath/a:} など → {@code OTHER_CODE}</li>
 * </ul>
 * 起動後に Attach API で動的に読み込まれたエージェントは JVM 引数に現れないため検出できない(既知の限界)。
 */
public final class AgentScanner {
    private static final String[] ENV_VARS = {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"};

    private AgentScanner() {}

    public static List<EntrySeed> scan(List<String> jvmArgs, Map<String, String> env, Path workingDir, Hasher cache) {
        List<String> all = new ArrayList<>(jvmArgs);
        for (String var : ENV_VARS) {
            String v = env.get(var);
            if (v != null && !v.isBlank()) {
                for (String part : v.trim().split("\\s+")) {
                    all.add(part);
                }
            }
        }

        Set<String> dedupe = new LinkedHashSet<>();
        List<EntrySeed> out = new ArrayList<>();
        for (String arg : all) {
            for (EntrySeed seed : parse(arg, workingDir, cache)) {
                if (dedupe.add(seed.kind() + "|" + seed.id() + "|" + seed.sha256())) {
                    out.add(seed);
                }
            }
        }
        return out;
    }

    static List<EntrySeed> parse(String arg, Path workingDir, Hasher cache) {
        List<EntrySeed> out = new ArrayList<>();
        if (arg.startsWith("-javaagent:")) {
            out.add(fileSeed(EntryKind.AGENT, stripOptions(arg.substring("-javaagent:".length())), workingDir, cache));
        } else if (arg.startsWith("-agentpath:")) {
            out.add(fileSeed(EntryKind.AGENT, stripOptions(arg.substring("-agentpath:".length())), workingDir, cache));
        } else if (arg.startsWith("-agentlib:")) {
            String name = stripOptions(arg.substring("-agentlib:".length()));
            String id = "agentlib:" + name;
            out.add(new EntrySeed(EntryKind.AGENT, id, "", Digests.hex(Digests.sha256(id.getBytes(StandardCharsets.UTF_8))), null));
        } else if (arg.startsWith("-Xbootclasspath/a:") || arg.startsWith("-Xbootclasspath/p:")) {
            for (String p : arg.substring("-Xbootclasspath/a:".length()).split(java.io.File.pathSeparator)) {
                if (!p.isEmpty()) {
                    out.add(fileSeed(EntryKind.OTHER_CODE, p, workingDir, cache));
                }
            }
        }
        return out;
    }

    /** JVM は最初の '=' でパスとオプションを分ける。 */
    private static String stripOptions(String value) {
        int eq = value.indexOf('=');
        return eq < 0 ? value : value.substring(0, eq);
    }

    private static EntrySeed fileSeed(EntryKind kind, String rawPath, Path workingDir, Hasher cache) {
        Path p = workingDir.resolve(rawPath).normalize();
        String name = p.getFileName() == null ? rawPath : p.getFileName().toString();
        String sha;
        try {
            sha = cache.sha256(p);
        } catch (IOException e) {
            sha = ModScanner.UNREADABLE_SHA;
        }
        return new EntrySeed(kind, name, "", sha, Files.isRegularFile(p) ? p : null);
    }
}
