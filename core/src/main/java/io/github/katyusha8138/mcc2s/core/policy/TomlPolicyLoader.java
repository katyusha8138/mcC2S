// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import com.electronwill.nightconfig.core.UnmodifiableConfig;
import com.electronwill.nightconfig.toml.TomlParser;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * TOML のポリシー設定を {@link PolicyConfig} に読み込む。night-config は Forge / NeoForge が同梱している。
 * セキュリティ設定なので、未知のキー(タイプミス)・型違い・曖昧なホワイトリストはすべてエラーにする。
 */
public final class TomlPolicyLoader {
    private static final Set<String> TOP_KEYS = Set.of(
            "mode", "scopes", "handshake_timeout_seconds", "show_details_to_player", "proof_rate_percent",
            "require_reference", "reverify", "mods", "libraries", "resource_packs", "shader_packs", "agents",
            "other_code");
    private static final Set<String> REVERIFY_KEYS = Set.of("enabled", "on_change", "min_seconds", "max_seconds");
    private static final Set<String> SECTION_KEYS = Set.of("match", "allow_server_baseline", "allow");
    private static final Set<String> ALLOW_KEYS = Set.of("id", "version", "sha256", "note");

    private static final String[][] SECTIONS = {
        {"mods", "MOD"},
        {"libraries", "LIBRARY"},
        {"resource_packs", "RESOURCE_PACK"},
        {"shader_packs", "SHADER_PACK"},
        {"agents", "AGENT"},
        {"other_code", "OTHER_CODE"},
    };

    private TomlPolicyLoader() {}

    /** 同梱の既定設定テンプレート(コメント付き)。初回起動時に設定ファイルとして書き出す。 */
    public static String defaultTemplate() {
        try (InputStream in = TomlPolicyLoader.class.getResourceAsStream("/io/github/katyusha8138/mcc2s/default-policy.toml")) {
            if (in == null) {
                throw new IllegalStateException("default-policy.toml missing from jar");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PolicyConfig parse(String toml) throws PolicyConfigException {
        UnmodifiableConfig root;
        try {
            root = new TomlParser().parse(toml);
        } catch (RuntimeException e) {
            throw new PolicyConfigException("invalid TOML: " + e.getMessage(), e);
        }
        checkKeys(root, "", TOP_KEYS);

        PolicyConfig.Builder b = PolicyConfig.builder();
        try {
            b.mode(parseEnum(EnforcementMode.class, str(root, "mode", "enforce"), "mode"));
            b.proofRatePercent(integer(root, "proof_rate_percent", 20));
            b.requireReference(bool(root, "require_reference", false));
            b.handshakeTimeoutSeconds(integer(root, "handshake_timeout_seconds", 30));
            b.showDetailsToPlayer(bool(root, "show_details_to_player", false));
            b.scopes(scopes(root));

            Object rv = root.get("reverify");
            if (rv != null) {
                UnmodifiableConfig r = table(rv, "reverify");
                checkKeys(r, "reverify.", REVERIFY_KEYS);
                b.reverify(bool(r, "enabled", true), integer(r, "min_seconds", 300), integer(r, "max_seconds", 900));
                b.reverifyOnChange(bool(r, "on_change", true));
            }

            for (String[] sec : SECTIONS) {
                Object o = root.get(sec[0]);
                if (o != null) {
                    b.kind(EntryKind.valueOf(sec[1]), kindPolicy(table(o, sec[0]), sec[0]));
                }
            }
            return b.build();
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException(e.getMessage(), e);
        }
    }

    private static KindPolicy kindPolicy(UnmodifiableConfig sec, String name) throws PolicyConfigException {
        checkKeys(sec, name + ".", SECTION_KEYS);
        MatchMode match = parseEnum(MatchMode.class, str(sec, "match", "hash"), name + ".match");
        boolean baseline = bool(sec, "allow_server_baseline", true);
        List<AllowEntry> allow = new ArrayList<>();
        Object list = sec.get("allow");
        if (list != null) {
            if (!(list instanceof List)) {
                throw new PolicyConfigException(name + ".allow must be an array of tables ([[" + name + ".allow]])");
            }
            int i = 0;
            for (Object item : (List<?>) list) {
                String where = name + ".allow[" + (i++) + "]";
                UnmodifiableConfig t = table(item, where);
                checkKeys(t, where + ".", ALLOW_KEYS);
                try {
                    allow.add(new AllowEntry(str(t, "id", null), str(t, "version", null), hashes(t, where), str(t, "note", "")));
                } catch (IllegalArgumentException e) {
                    throw new PolicyConfigException(where + ": " + e.getMessage(), e);
                }
            }
        }
        try {
            return new KindPolicy(match, baseline, allow);
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException("[" + name + "] " + e.getMessage(), e);
        }
    }

    private static Set<String> hashes(UnmodifiableConfig t, String where) throws PolicyConfigException {
        Object o = t.get("sha256");
        Set<String> out = new LinkedHashSet<>();
        if (o == null) {
            return out;
        }
        if (o instanceof String) {
            out.add((String) o);
        } else if (o instanceof List) {
            for (Object h : (List<?>) o) {
                if (!(h instanceof String)) {
                    throw new PolicyConfigException(where + ".sha256 must contain only strings");
                }
                out.add((String) h);
            }
        } else {
            throw new PolicyConfigException(where + ".sha256 must be a string or an array of strings");
        }
        return out;
    }

    private static Set<Scope> scopes(UnmodifiableConfig root) throws PolicyConfigException {
        Object o = root.get("scopes");
        if (o == null) {
            return EnumSet.allOf(Scope.class);
        }
        if (!(o instanceof List)) {
            throw new PolicyConfigException("scopes must be an array of strings");
        }
        EnumSet<Scope> out = EnumSet.noneOf(Scope.class);
        for (Object s : (List<?>) o) {
            if (!(s instanceof String)) {
                throw new PolicyConfigException("scopes must contain only strings");
            }
            out.add(parseEnum(Scope.class, (String) s, "scopes"));
        }
        return out;
    }

    private static void checkKeys(UnmodifiableConfig c, String prefix, Set<String> allowed) throws PolicyConfigException {
        for (Map.Entry<String, Object> e : c.valueMap().entrySet()) {
            if (!allowed.contains(e.getKey())) {
                throw new PolicyConfigException("unknown key '" + prefix + e.getKey() + "' (typo?)");
            }
        }
    }

    private static UnmodifiableConfig table(Object o, String where) throws PolicyConfigException {
        if (o instanceof UnmodifiableConfig) {
            return (UnmodifiableConfig) o;
        }
        throw new PolicyConfigException(where + " must be a table");
    }

    private static String str(UnmodifiableConfig c, String key, String def) throws PolicyConfigException {
        Object o = c.get(key);
        if (o == null) {
            return def;
        }
        if (o instanceof String) {
            return (String) o;
        }
        throw new PolicyConfigException(key + " must be a string");
    }

    private static int integer(UnmodifiableConfig c, String key, int def) throws PolicyConfigException {
        Object o = c.get(key);
        if (o == null) {
            return def;
        }
        if (o instanceof Number && !(o instanceof Double) && !(o instanceof Float)) {
            long v = ((Number) o).longValue();
            if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
                throw new PolicyConfigException(key + " is out of range");
            }
            return (int) v;
        }
        throw new PolicyConfigException(key + " must be an integer");
    }

    private static boolean bool(UnmodifiableConfig c, String key, boolean def) throws PolicyConfigException {
        Object o = c.get(key);
        if (o == null) {
            return def;
        }
        if (o instanceof Boolean) {
            return (Boolean) o;
        }
        throw new PolicyConfigException(key + " must be true or false");
    }

    private static <E extends Enum<E>> E parseEnum(Class<E> type, String value, String key) throws PolicyConfigException {
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new PolicyConfigException(key + ": unknown value '" + value + "'");
        }
    }
}
