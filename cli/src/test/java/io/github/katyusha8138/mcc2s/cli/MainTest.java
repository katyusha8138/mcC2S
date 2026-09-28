// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.common.Log;
import io.github.katyusha8138.mcc2s.common.ServerFiles;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.TomlPolicyLoader;
import io.github.katyusha8138.mcc2s.core.release.OfficialBuilds;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainTest {
    @TempDir Path tmp;

    private static final class Result {
        final int code;
        final String out;
        final String err;

        Result(int code, String out, String err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }
    }

    private static Result run(String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        return new Result(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    private Path zip(String name, String... entries) throws IOException {
        Path p = tmp.resolve(name);
        try (ZipOutputStream z = new ZipOutputStream(Files.newOutputStream(p))) {
            for (int i = 0; i < entries.length; i += 2) {
                z.putNextEntry(new ZipEntry(entries[i]));
                z.write(entries[i + 1].getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return p;
    }

    private static String sha(Path p) throws IOException {
        return Digests.hex(Digests.sha256(p));
    }

    // ---- 使い方 ----

    @Test
    void helpAndUsageErrors() {
        assertEquals(0, run("help").code);
        assertTrue(run("help").out.contains("sign-release"));
        assertEquals(2, run().code);
        Result unknown = run("frobnicate");
        assertEquals(2, unknown.code);
        assertTrue(unknown.err.contains("不明なコマンド"));
        assertEquals(2, run("hash", "--nope", "x").code);
        assertEquals(2, run("hash").code);
        assertEquals(2, run("keygen").code);
        assertEquals(2, run("hash", "--kind", "banana", "x").code);
    }

    // ---- hash ----

    @Test
    void hashPrintsSha256ForFilesAndFolders() throws Exception {
        Path f = zip("a.jar", "x.txt", "hello");
        Path dir = Files.createDirectories(tmp.resolve("pack"));
        Files.writeString(dir.resolve("pack.mcmeta"), "{}");

        Result r = run("hash", f.toString(), dir.toString());
        assertEquals(0, r.code);
        assertTrue(r.out.contains(sha(f) + "  " + f));
        assertTrue(r.out.contains(Digests.treeHashHex(dir)));
    }

    @Test
    void hashReportsMissingPathsButKeepsGoing() throws Exception {
        Path f = zip("a.jar", "x.txt", "hello");
        Result r = run("hash", tmp.resolve("missing.jar").toString(), f.toString());
        assertEquals(1, r.code);
        assertTrue(r.err.contains("見つかりません"));
        assertTrue(r.out.contains(sha(f)));
    }

    @Test
    void hashTomlReadsModIdAndVersionFromTheJarAndProducesAValidPolicy() throws Exception {
        Path jar = zip(
                "example-1.2.3.jar",
                "META-INF/neoforge.mods.toml",
                "modLoader = \"javafml\"\n[[mods]]\nmodId = \"examplemod\"\nversion = \"1.2.3\"\n");
        Result r = run("hash", "--toml", jar.toString());
        assertEquals(0, r.code, r.err);
        assertTrue(r.out.contains("[[mods.allow]]"));
        assertTrue(r.out.contains("id = \"examplemod\"") && r.out.contains("version = \"1.2.3\""));

        // 出力をそのまま policy.toml に貼れる(ハッシュモードで有効な設定になる)
        PolicyConfig cfg = TomlPolicyLoader.parse(r.out);
        assertEquals("examplemod", cfg.kindPolicy(EntryKind.MOD).allow().get(0).id());
        assertTrue(cfg.kindPolicy(EntryKind.MOD).allow().get(0).sha256().contains(sha(jar)));
    }

    @Test
    void hashTomlResolvesVersionPlaceholdersFromTheManifest() throws Exception {
        Path jar = zip(
                "ph.jar",
                "META-INF/neoforge.mods.toml",
                "[[mods]]\nmodId = \"ph\"\nversion = \"${file.jarVersion}\"\n",
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\nImplementation-Version: 9.9.9\r\n\r\n");
        Result r = run("hash", "--toml", jar.toString());
        assertTrue(r.out.contains("version = \"9.9.9\""), r.out);
    }

    @Test
    void hashTomlFallsBackToTheFileNameAndSupportsOtherKindsAndOverrides() throws Exception {
        Path plain = zip("cool-mod.jar", "x", "y");
        assertTrue(run("hash", "--toml", plain.toString()).out.contains("id = \"cool-mod\""));

        Path pack = zip("Faithful.zip", "pack.mcmeta", "{}");
        Result rp = run("hash", "--toml", "--kind", "resource-pack", pack.toString());
        assertTrue(rp.out.contains("[[resource_packs.allow]]") && rp.out.contains("id = \"Faithful.zip\""));
        assertEquals(1, TomlPolicyLoader.parse(rp.out).kindPolicy(EntryKind.RESOURCE_PACK).allow().size());

        Result ov = run("hash", "--toml", "--id", "custom", "--version", "0.1", plain.toString());
        assertTrue(ov.out.contains("id = \"custom\"") && ov.out.contains("version = \"0.1\""));
        assertEquals(2, run("hash", "--toml", "--id", "x", plain.toString(), pack.toString()).code);
    }

    // ---- keygen / pubkey ----

    @Test
    void keygenCreatesAPrivateKeyFileAndRefusesToOverwriteIt() throws Exception {
        Path key = tmp.resolve("release.identity");
        Result r = run("keygen", "--out", key.toString());
        assertEquals(0, r.code, r.err);
        assertTrue(Files.exists(key));
        assertTrue(r.out.contains("MCC2S_RELEASE_KEY"));
        try {
            assertEquals(
                    Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), Files.getPosixFilePermissions(key));
        } catch (UnsupportedOperationException e) {
            // POSIX でない環境
        }

        String before = Files.readString(key);
        Result again = run("keygen", "--out", key.toString());
        assertEquals(1, again.code);
        assertEquals(before, Files.readString(key), "an existing key must never be overwritten silently");
        assertEquals(0, run("keygen", "--out", key.toString(), "--force").code);
        assertFalse(before.equals(Files.readString(key)));
    }

    @Test
    void pubkeyMatchesWhatKeygenPrinted() throws Exception {
        Path key = tmp.resolve("k.identity");
        String printed = run("keygen", "--out", key.toString()).out;
        String pub = run("pubkey", "--identity", key.toString()).out.trim();
        assertTrue(printed.contains(pub));
        assertEquals(43, pub.length()); // 32 バイトの base64url(パディングなし)
        assertEquals(1, run("pubkey", "--identity", tmp.resolve("nope").toString()).code);
    }

    // ---- sign-release / verify-release ----

    private Path newKey(String name) {
        Path key = tmp.resolve(name);
        assertEquals(0, run("keygen", "--out", key.toString()).code);
        return key;
    }

    @Test
    void signAndVerifyRoundTrip() throws Exception {
        Path key = newKey("k.identity");
        Path jar = zip("mcc2s.jar", "a", "b");
        Path out = tmp.resolve("official-builds.txt");
        Result s = run("sign-release", "--key", key.toString(), "--version", "0.2.0", "--loader", "neoforge-1.21.1", "--out", out.toString(), jar.toString());
        assertEquals(0, s.code, s.err);

        String pub = run("pubkey", "--identity", key.toString()).out.trim();
        Result v = run("verify-release", "--pubkey", pub, out.toString());
        assertEquals(0, v.code, v.err);
        assertTrue(v.out.contains(sha(jar)) && v.out.contains("0.2.0") && v.out.contains("neoforge-1.21.1"));

        // 公開鍵はファイルでも渡せる
        Path pubFile = tmp.resolve("release-public-key.txt");
        Files.writeString(pubFile, pub + "\n");
        assertEquals(0, run("verify-release", "--pubkey", pubFile.toString(), out.toString()).code);
    }

    @Test
    void verifyRejectsTamperedListsAndWrongKeys() throws Exception {
        Path key = newKey("k.identity");
        Path jar = zip("mcc2s.jar", "a", "b");
        Path out = tmp.resolve("official-builds.txt");
        run("sign-release", "--key", key.toString(), "--version", "1", "--loader", "x", "--out", out.toString(), jar.toString());
        String pub = run("pubkey", "--identity", key.toString()).out.trim();

        // 改造ビルドのハッシュを差し込む
        String evil = Digests.hex(Digests.sha256("patched".getBytes(StandardCharsets.UTF_8)));
        Path tampered = tmp.resolve("tampered.txt");
        Files.writeString(tampered, Files.readString(out).replace("signature ", "build " + evil + " 9 x\nsignature "));
        Result t = run("verify-release", "--pubkey", pub, tampered.toString());
        assertEquals(1, t.code);
        assertTrue(t.err.contains("検証に失敗"));

        String otherPub = run("pubkey", "--identity", newKey("other.identity").toString()).out.trim();
        assertEquals(1, run("verify-release", "--pubkey", otherPub, out.toString()).code);
        assertEquals(1, run("verify-release", "--pubkey", "!!!", out.toString()).code);
    }

    @Test
    void signWithBaseAccumulatesPastBuildsAndKeepsTheirMetadata() throws Exception {
        Path key = newKey("k.identity");
        Path jar1 = zip("v1.jar", "1", "1");
        Path jar2 = zip("v2.jar", "2", "2");
        Path list1 = tmp.resolve("list1.txt");
        Path list2 = tmp.resolve("list2.txt");

        assertEquals(0, run("sign-release", "--key", key.toString(), "--version", "0.1.0", "--loader", "neoforge-1.21.1", "--out", list1.toString(), jar1.toString()).code);
        Result second = run("sign-release", "--key", key.toString(), "--version", "0.2.0", "--loader", "neoforge-1.21.1",
                "--base", list1.toString(), "--out", list2.toString(), jar2.toString(), jar1.toString());
        assertEquals(0, second.code, second.err);
        assertTrue(second.out.contains("すでに掲載済み"), "re-listing the same jar must not duplicate it");

        String pub = run("pubkey", "--identity", key.toString()).out.trim();
        Result v = run("verify-release", "--pubkey", pub, list2.toString());
        assertTrue(v.out.contains("2 件"));
        assertTrue(v.out.contains(sha(jar1) + "  0.1.0"), "the old build keeps its own version");
        assertTrue(v.out.contains(sha(jar2) + "  0.2.0"));
    }

    @Test
    void signRefusesABaseThatIsNotSignedByTheSameKey() throws Exception {
        Path attackerKey = newKey("attacker.identity");
        Path realKey = newKey("real.identity");
        Path jar = zip("v1.jar", "1", "1");
        Path forgedBase = tmp.resolve("forged.txt");
        run("sign-release", "--key", attackerKey.toString(), "--version", "6.6.6", "--loader", "x", "--out", forgedBase.toString(), jar.toString());

        Path out = tmp.resolve("out.txt");
        Result r = run("sign-release", "--key", realKey.toString(), "--version", "1", "--loader", "x", "--base", forgedBase.toString(), "--out", out.toString(), jar.toString());
        assertEquals(1, r.code);
        assertFalse(Files.exists(out), "nothing may be signed on top of an unverified base");
    }

    @Test
    void signValidatesItsInputs() throws Exception {
        Path key = newKey("k.identity");
        assertEquals(2, run("sign-release", "--key", key.toString(), "--version", "1").code);
        assertEquals(1, run("sign-release", "--key", key.toString(), "--version", "1", "--loader", "x", tmp.resolve("no.jar").toString()).code);
        Path jar = zip("v.jar", "1", "1");
        // 空白を含むバージョンは一覧の書式を壊すので拒否する
        assertEquals(1, run("sign-release", "--key", key.toString(), "--version", "1 2", "--loader", "x", jar.toString()).code);
    }

    // ---- trustfile / rotate-secret ----

    @Test
    void trustfileRegeneratesADistributableFileWithoutThePrivateKey() throws Exception {
        Path config = tmp.resolve("config/mcc2s");
        ServerFiles.Loaded loaded = ServerFiles.loadOrCreate(config, "orig", Log.stdout(), new SecureRandom());
        Path out = tmp.resolve("custom.mc2strust");
        Result r = run("trustfile", "--config", config.toString(), "--label", "Kanto SMP", "--out", out.toString());
        assertEquals(0, r.code, r.err);

        String text = Files.readString(out);
        assertFalse(text.contains("private_key"));
        TrustFile tf = TrustFile.parse(text);
        assertEquals("Kanto SMP", tf.label());
        assertArrayEquals(loaded.identity().publicKey(), tf.serverPublicKey());

        // --out なしなら trust/ に上書き生成する
        assertEquals(0, run("trustfile", "--config", config.toString()).code);
        assertEquals(1, run("trustfile", "--config", tmp.resolve("empty").toString()).code);
    }

    @Test
    void rotateSecretKeepsOldKeysForAGraceAndIsCapped() throws Exception {
        Path config = tmp.resolve("config/mcc2s");
        ServerFiles.loadOrCreate(config, "s", Log.stdout(), new SecureRandom());
        PackSecret original = ServerFiles.readSecrets(config).get(0);

        Result r = run("rotate-secret", "--config", config.toString(), "--label", "s");
        assertEquals(0, r.code, r.err);
        List<PackSecret> after = ServerFiles.readSecrets(config);
        assertEquals(2, after.size());
        assertFalse(java.util.Arrays.equals(original.value(), after.get(0).value()), "a new current secret");
        assertArrayEquals(original.value(), after.get(1).value(), "the previous current is kept as a grace key");

        // 新しい信頼ファイルには新しい現行鍵が入る
        Path trust = config.resolve("trust").resolve(Files.list(config.resolve("trust")).findFirst().orElseThrow().getFileName());
        assertArrayEquals(after.get(0).value(), TrustFile.parse(Files.readString(trust)).packSecret().value());

        for (int i = 0; i < 6; i++) {
            assertEquals(0, run("rotate-secret", "--config", config.toString()).code);
        }
        assertEquals(1 + ServerFiles.MAX_PREVIOUS_SECRETS, ServerFiles.readSecrets(config).size(), "old keys must not pile up forever");
    }
}
