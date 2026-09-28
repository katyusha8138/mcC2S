// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.handshake.TrustStore;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.EnforcementMode;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfigException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ServerFilesTest {
    @TempDir Path tmp;
    private final Log log = Log.stdout();

    @Test
    void firstStartCreatesEverythingAndSecondStartReusesIt() throws Exception {
        Path cfg = tmp.resolve("config/mcc2s");
        ServerFiles.Loaded a = ServerFiles.loadOrCreate(cfg, "My Server", log, Harness.RND);
        assertTrue(Files.exists(cfg.resolve(ServerFiles.POLICY)));
        assertTrue(Files.exists(cfg.resolve(ServerFiles.IDENTITY)));
        assertTrue(Files.exists(cfg.resolve(ServerFiles.SECRETS)));
        assertTrue(Files.isDirectory(cfg.resolve(ServerFiles.REFERENCE_DIR)));
        assertTrue(Files.exists(a.trustFilePath()));
        assertEquals(EnforcementMode.ENFORCE, a.policy().mode());

        ServerFiles.Loaded b = ServerFiles.loadOrCreate(cfg, "My Server", log, Harness.RND);
        assertArrayEquals(a.identity().publicKey(), b.identity().publicKey());
        assertArrayEquals(a.secrets().all().get(0).value(), b.secrets().all().get(0).value());
        assertEquals(a.trustFilePath(), b.trustFilePath());
    }

    @Test
    void secretFilesAreOwnerOnlyOnPosix() throws Exception {
        Path cfg = tmp.resolve("cfg");
        ServerFiles.loadOrCreate(cfg, "s", log, Harness.RND);
        for (String name : new String[] {ServerFiles.IDENTITY, ServerFiles.SECRETS}) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(cfg.resolve(name));
                assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms, name);
            } catch (UnsupportedOperationException e) {
                // POSIX でない環境では検査しない
            }
        }
    }

    @Test
    void generatedTrustFileIsUsableByAClientAndContainsNoPrivateKey() throws Exception {
        Path cfg = tmp.resolve("cfg");
        ServerFiles.Loaded loaded = ServerFiles.loadOrCreate(cfg, "Kanto SMP", log, Harness.RND);
        String trustText = Files.readString(loaded.trustFilePath(), StandardCharsets.UTF_8);
        assertFalse(trustText.contains("private_key"));

        // クライアントの信頼ディレクトリに置くと、そのサーバーの鍵 ID で引ける
        Path trustDir = Files.createDirectories(tmp.resolve("client-trust"));
        Files.copy(loaded.trustFilePath(), trustDir.resolve(loaded.trustFilePath().getFileName()));
        TrustStore ts = TrustFiles.load(trustDir, log);
        assertTrue(ts.find(loaded.identity().keyId()).isPresent());
        assertEquals("Kanto SMP", ts.find(loaded.identity().keyId()).orElseThrow().label());
    }

    @Test
    void badTrustFilesAreSkippedWithoutBreakingGoodOnes() throws Exception {
        Path cfg = tmp.resolve("cfg");
        ServerFiles.Loaded loaded = ServerFiles.loadOrCreate(cfg, "s", log, Harness.RND);
        Path trustDir = Files.createDirectories(tmp.resolve("client-trust"));
        Files.copy(loaded.trustFilePath(), trustDir.resolve("good.mc2strust"));
        Files.writeString(trustDir.resolve("broken.mc2strust"), "garbage");
        Files.writeString(trustDir.resolve("notes.txt"), "ignored");
        TrustStore ts = TrustFiles.load(trustDir, log);
        assertTrue(ts.find(loaded.identity().keyId()).isPresent());
        assertTrue(TrustFiles.load(tmp.resolve("missing"), log).isEmpty());
    }

    @Test
    void secretRotationKeepsPreviousKeysAcceptedAndNewFilesUseTheCurrentKey() throws Exception {
        PackSecret cur = PackSecret.generate(Harness.RND);
        PackSecret old1 = PackSecret.generate(Harness.RND);
        PackSecret old2 = PackSecret.generate(Harness.RND);
        List<PackSecret> parsed = ServerFiles.parseSecrets(ServerFiles.secretsText(List.of(cur, old1, old2)));
        assertEquals(3, parsed.size());
        assertArrayEquals(cur.value(), parsed.get(0).value());
        assertArrayEquals(old2.value(), parsed.get(2).value());

        // ファイルを手で書き換えてローテーションした後の起動
        Path cfg = tmp.resolve("cfg");
        ServerFiles.loadOrCreate(cfg, "s", log, Harness.RND);
        Files.writeString(cfg.resolve(ServerFiles.SECRETS), ServerFiles.secretsText(List.of(cur, old1)));
        ServerFiles.Loaded after = ServerFiles.loadOrCreate(cfg, "s", log, Harness.RND);
        assertEquals(2, after.secrets().all().size());
        assertTrue(after.secrets().find(old1.id()).isPresent());
        String trust = Files.readString(after.trustFilePath());
        assertTrue(trust.contains(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(cur.value())));
    }

    @Test
    void malformedSecretFilesAreRejected() {
        assertThrows(GeneralSecurityException.class, () -> ServerFiles.parseSecrets("nonsense"));
        assertThrows(GeneralSecurityException.class, () -> ServerFiles.parseSecrets("mcc2s-pack-secrets-v1\n"));
        assertThrows(GeneralSecurityException.class, () -> ServerFiles.parseSecrets("mcc2s-pack-secrets-v1\ncurrent = !!!\n"));
        assertThrows(GeneralSecurityException.class, () -> ServerFiles.parseSecrets("mcc2s-pack-secrets-v1\nother = AAAA\n"));
    }

    @Test
    void invalidPolicyFailsStartupInsteadOfSilentlyRunningOpen() throws Exception {
        Path cfg = tmp.resolve("cfg");
        ServerFiles.loadOrCreate(cfg, "s", log, Harness.RND);
        Files.writeString(cfg.resolve(ServerFiles.POLICY), "mode = \"enforc\"\n");
        assertThrows(PolicyConfigException.class, () -> ServerFiles.loadOrCreate(cfg, "s", log, Harness.RND));
    }

    @Test
    void officialBuildsAreEmptyWithoutAnEmbeddedReleaseKey() {
        assertEquals(0, ServerFiles.loadOfficialBuilds(tmp, log).hashes().size());
    }

    // ---- ServerRuntime(起動処理の統合)----

    @Test
    void serverRuntimeAssemblesBaselineReferencesAndTrustedSelf() throws Exception {
        Path game = Files.createDirectories(tmp.resolve("game"));
        Path mods = Files.createDirectories(game.resolve("mods"));
        Path create = mods.resolve("create.jar");
        Files.writeString(create, "create bytes");
        Files.writeString(mods.resolve("stray.jar"), "stray bytes");
        Path self = mods.resolve("mcc2s.jar");
        Files.writeString(self, "mcc2s bytes");
        Path refDir = Files.createDirectories(game.resolve("config/mcc2s/reference"));
        Files.writeString(refDir.resolve("sodium.jar"), "sodium bytes");

        List<LoadedMod> loaded = List.of(
                new LoadedMod(create, List.of("create"), "6.0"), new LoadedMod(self, List.of("mcc2s"), "0.1.0"));
        ServerRuntime.Inputs in = new ServerRuntime.Inputs(
                game.resolve("config/mcc2s"), mods, game.resolve("logs/mcc2s"), loaded, Set.of("minecraft", "neoforge"), self, "0.1.0", "Test", log);
        try (ServerRuntime rt = ServerRuntime.start(in, Harness.RND)) {
            ServerContext ctx = rt.context();
            // baseline: create(MOD) + mcc2s(MOD として登録されている自分自身) + stray(LIBRARY)
            assertEquals(3, ctx.baseline().size());
            assertTrue(ctx.baseline().stream().anyMatch(e -> e.kind() == EntryKind.LIBRARY && e.id().equals("stray.jar")));
            assertEquals(1, ctx.trustedSelfHashes().size());
            // 参照: create, stray, mcc2s(自分と同一ハッシュ), reference/sodium
            String sodiumSha = new HashCache().sha256(refDir.resolve("sodium.jar"));
            assertTrue(ctx.references().open(EntryKind.MOD, sodiumSha).isPresent());
            assertTrue(Files.exists(rt.trustFilePath()));
        }
    }
}
