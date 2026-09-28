// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;

class TomlPolicyLoaderTest {
    private static final String H1 = Fixtures.sha("one");
    private static final String H2 = Fixtures.sha("two");

    @Test
    void shippedDefaultTemplateParsesAndMatchesBuiltInDefaults() throws Exception {
        PolicyConfig cfg = TomlPolicyLoader.parse(TomlPolicyLoader.defaultTemplate());
        PolicyConfig defaults = PolicyConfig.defaults();
        assertEquals(defaults.mode(), cfg.mode());
        assertEquals(defaults.scopes(), cfg.scopes());
        assertEquals(defaults.proofRatePercent(), cfg.proofRatePercent());
        assertEquals(defaults.requireReference(), cfg.requireReference());
        assertEquals(defaults.handshakeTimeoutSeconds(), cfg.handshakeTimeoutSeconds());
        assertEquals(defaults.showDetailsToPlayer(), cfg.showDetailsToPlayer());
        assertEquals(defaults.reverifyEnabled(), cfg.reverifyEnabled());
        assertEquals(defaults.reverifyMinSeconds(), cfg.reverifyMinSeconds());
        assertEquals(defaults.reverifyMaxSeconds(), cfg.reverifyMaxSeconds());
        for (EntryKind k : EntryKind.values()) {
            if (k != EntryKind.SELF) {
                assertEquals(MatchMode.HASH, cfg.kindPolicy(k).match());
                assertTrue(cfg.kindPolicy(k).allow().isEmpty());
            }
        }
    }

    @Test
    void emptyFileYieldsSafeDefaults() throws Exception {
        PolicyConfig cfg = TomlPolicyLoader.parse("");
        assertEquals(EnforcementMode.ENFORCE, cfg.mode());
        assertEquals(EnumSet.allOf(Scope.class), cfg.scopes());
    }

    @Test
    void fullConfigIsReadCorrectly() throws Exception {
        String toml = "mode = \"audit\"\n"
                + "scopes = [\"mods\", \"resource_packs\"]\n"
                + "handshake_timeout_seconds = 45\n"
                + "show_details_to_player = true\n"
                + "proof_rate_percent = 35\n"
                + "require_reference = true\n"
                + "[reverify]\nenabled = false\nmin_seconds = 60\nmax_seconds = 120\n"
                + "[mods]\nmatch = \"hash\"\nallow_server_baseline = false\n"
                + "[[mods.allow]]\nid = \"sodium\"\nsha256 = [\"" + H1 + "\", \"" + H2.toUpperCase() + "\"]\nnote = \"perf\"\n"
                + "[[mods.allow]]\nsha256 = \"" + H2 + "\"\n"
                + "[resource_packs]\nmatch = \"id\"\n[[resource_packs.allow]]\nid = \"file/ok.zip\"\n";
        PolicyConfig cfg = TomlPolicyLoader.parse(toml);
        assertEquals(EnforcementMode.AUDIT, cfg.mode());
        assertEquals(EnumSet.of(Scope.MODS, Scope.RESOURCE_PACKS), cfg.scopes());
        assertEquals(45, cfg.handshakeTimeoutSeconds());
        assertTrue(cfg.showDetailsToPlayer());
        assertEquals(35, cfg.proofRatePercent());
        assertTrue(cfg.requireReference());
        assertFalse(cfg.reverifyEnabled());
        assertEquals(60, cfg.reverifyMinSeconds());
        assertFalse(cfg.kindPolicy(EntryKind.MOD).allowBaseline());
        assertEquals(2, cfg.kindPolicy(EntryKind.MOD).allow().size());
        assertEquals("sodium", cfg.kindPolicy(EntryKind.MOD).allow().get(0).id());
        assertTrue(cfg.kindPolicy(EntryKind.MOD).allow().get(0).sha256().contains(H2)); // 大文字は正規化される
        assertEquals(MatchMode.ID, cfg.kindPolicy(EntryKind.RESOURCE_PACK).match());
    }

    private static void rejects(String toml, String messagePart) {
        PolicyConfigException e = assertThrows(PolicyConfigException.class, () -> TomlPolicyLoader.parse(toml), toml);
        assertTrue(e.getMessage().contains(messagePart), "expected '" + messagePart + "' in: " + e.getMessage());
    }

    @Test
    void typosAndMisconfigurationsAreRejected() {
        rejects("mod = \"enforce\"", "unknown key 'mod'");
        rejects("mode = \"enforc\"", "unknown value");
        rejects("mode = 3", "must be a string");
        rejects("[mods]\nmatch = \"fuzzy\"", "unknown value");
        rejects("[mods]\nallow_server_basline = true", "unknown key 'mods.allow_server_basline'");
        rejects("scopes = [\"mods\", \"rods\"]", "unknown value");
        rejects("scopes = []", "must not be empty");
        rejects("scopes = \"mods\"", "array");
        rejects("proof_rate_percent = 150", "0..100");
        rejects("proof_rate_percent = 2.5", "integer");
        rejects("handshake_timeout_seconds = 1", "5..300");
        rejects("require_reference = \"yes\"", "true or false");
        rejects("[reverify]\nmin_seconds = 10", "reverify");
        rejects("[reverify]\nmin_seconds = 500\nmax_seconds = 100", "reverify");
        rejects("this is not toml", "invalid TOML");
    }

    @Test
    void overlyBroadAllowEntriesAreRejected() {
        // hash モードで sha256 の無い許可(ID だけで全バージョンを通してしまう)は起動時エラー
        rejects("[[mods.allow]]\nid = \"sodium\"", "requires sha256");
        rejects("[mods]\nmatch = \"hash\"\n[[mods.allow]]\nid = \"sodium\"", "requires sha256");
        rejects("[mods]\nmatch = \"id_version\"\n[[mods.allow]]\nid = \"sodium\"", "id and version");
        rejects("[mods]\nmatch = \"id\"\n[[mods.allow]]\nversion = \"1\"", "requires id");
        rejects("[[mods.allow]]\nnote = \"empty\"", "at least one");
        rejects("[[mods.allow]]\nsha256 = \"nothex\"", "invalid sha256");
        rejects("[[mods.allow]]\nsha256 = [1, 2]", "only strings");
        rejects("[[mods.allow]]\nsha256 = \"" + H1 + "\"\nextra = 1", "unknown key");
        rejects("[mods]\nallow = 5", "array of tables");
    }
}
