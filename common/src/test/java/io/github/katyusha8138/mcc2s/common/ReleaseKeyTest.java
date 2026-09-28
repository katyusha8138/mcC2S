// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.release.OfficialBuilds;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReleaseKeyTest {
    @TempDir Path tmp;

    private static java.io.InputStream stream(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void missingOrEmptyResourceMeansNoKey() throws Exception {
        assertTrue(ReleaseKey.parse(null).isEmpty());
        assertTrue(ReleaseKey.parse(stream("  \n")).isEmpty());
    }

    @Test
    void validKeyIsParsedIgnoringWhitespace() throws Exception {
        byte[] raw = new byte[32];
        Harness.RND.nextBytes(raw);
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        assertArrayEquals(raw, ReleaseKey.parse(stream("  " + b64 + "\r\n")).orElseThrow());
    }

    @Test
    void brokenKeysAreRejectedLoudly() {
        assertThrows(IllegalStateException.class, () -> ReleaseKey.parse(stream("!!!not-base64!!!")));
        assertThrows(IllegalStateException.class, () -> ReleaseKey.parse(stream("AAAA")));
    }

    @Test
    void thisTestBuildEmbedsNoKeyUnlessTheRepositoryHasOne() {
        // リポジトリに release/release-public-key.txt が無い間は鍵なし(最も厳格な動作)。あれば 32 バイトの鍵が読める。
        boolean repoHasKey = Files.exists(Path.of("..", "release", "release-public-key.txt"));
        assertEquals(repoHasKey, ReleaseKey.publicKey().isPresent());
    }

    @Test
    void withoutAKeyTheOfficialBuildsFileIsIgnoredAndOnlyTheSameBuildIsTrusted() throws Exception {
        // 鍵の無いビルドが、署名の付いた(=信頼できるかどうか検証できない)一覧を採用してはいけない
        Path cfg = Files.createDirectories(tmp.resolve("cfg"));
        Ed25519Identity someKey = Ed25519Identity.generate(Harness.RND);
        String list = OfficialBuilds.sign(
                OfficialBuilds.bodyOf(java.util.List.of(new OfficialBuilds.Build(Harness.sha("evil"), "9.9", "x"))), someKey);
        Files.writeString(cfg.resolve(ServerFiles.OFFICIAL_BUILDS), list);
        if (ReleaseKey.publicKey().isEmpty()) {
            assertEquals(0, ServerFiles.loadOfficialBuilds(cfg, Log.stdout()).hashes().size());
        }
    }
}
