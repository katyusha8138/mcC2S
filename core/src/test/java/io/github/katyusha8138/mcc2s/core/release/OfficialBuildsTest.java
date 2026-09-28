// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.release;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

class OfficialBuildsTest {
    private static final String A = Fixtures.sha("build-a");
    private static final String B = Fixtures.sha("build-b");

    private static String body() {
        return OfficialBuilds.HEADER + "\n"
                + "# release 0.1.0\n"
                + "build " + A + " 0.1.0 neoforge-1.21.1\n"
                + "build " + B + " 0.1.0 forge-1.20.1\n";
    }

    @Test
    void signedListVerifiesAndExposesHashes() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        String file = OfficialBuilds.sign(body(), release);
        OfficialBuilds ob = OfficialBuilds.parseAndVerify(file, release.publicKey());
        assertEquals(2, ob.hashes().size());
        assertTrue(ob.contains(A) && ob.contains(B));
        assertFalse(ob.contains(Fixtures.sha("patched")));
    }

    @Test
    void tamperedBodyIsRejected() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        String file = OfficialBuilds.sign(body(), release);
        String evilHash = Fixtures.sha("cheat-build");
        // 改造ビルドのハッシュを差し込む
        String tampered = file.replace("signature ", "build " + evilHash + " 9.9.9 x\nsignature ");
        assertThrows(GeneralSecurityException.class, () -> OfficialBuilds.parseAndVerify(tampered, release.publicKey()));
        // 既存行の書き換え
        String tampered2 = file.replace(A, evilHash);
        assertThrows(GeneralSecurityException.class, () -> OfficialBuilds.parseAndVerify(tampered2, release.publicKey()));
    }

    @Test
    void signatureByAnotherKeyIsRejected() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        Ed25519Identity attacker = Ed25519Identity.generate(Fixtures.RND);
        String file = OfficialBuilds.sign(body(), attacker);
        assertThrows(GeneralSecurityException.class, () -> OfficialBuilds.parseAndVerify(file, release.publicKey()));
    }

    @Test
    void missingOrGarbledSignatureIsRejected() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        assertThrows(GeneralSecurityException.class, () -> OfficialBuilds.parseAndVerify(body(), release.publicKey()));
        assertThrows(GeneralSecurityException.class,
                () -> OfficialBuilds.parseAndVerify(body() + "signature !!!\n", release.publicKey()));
        assertThrows(GeneralSecurityException.class,
                () -> OfficialBuilds.parseAndVerify(body() + "signature AAAA\n", release.publicKey()));
    }

    @Test
    void malformedBuildLinesAreRejectedEvenWhenSigned() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        String bad = OfficialBuilds.HEADER + "\nbuild nothex 0.1.0 x\n";
        String file = OfficialBuilds.sign(bad, release);
        assertThrows(GeneralSecurityException.class, () -> OfficialBuilds.parseAndVerify(file, release.publicKey()));
    }

    @Test
    void signRequiresHeader() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        assertThrows(IllegalArgumentException.class, () -> OfficialBuilds.sign("build x\n", release));
    }

    @Test
    void windowsLineEndingsVerifyTheSame() throws Exception {
        Ed25519Identity release = Ed25519Identity.generate(Fixtures.RND);
        String file = OfficialBuilds.sign(body(), release).replace("\n", "\r\n");
        assertEquals(2, OfficialBuilds.parseAndVerify(file, release.publicKey()).hashes().size());
    }
}
