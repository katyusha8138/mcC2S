// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.katyusha8138.mcc2s.core.handshake.HandshakeException.Reason;
import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ContextsTest {
    private static byte[] u(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void composeHasNoBoundaryAmbiguity() {
        assertFalse(Arrays.equals(Contexts.compose(u("ab"), u("c")), Contexts.compose(u("a"), u("bc"))));
        assertFalse(Arrays.equals(Contexts.compose(u("a"), u("b")), Contexts.compose(u("ab"))));
        assertFalse(Arrays.equals(Contexts.compose(), Contexts.compose(new byte[0])));
        assertArrayEquals(Contexts.compose(u("a"), u("b")), Contexts.compose(u("a"), u("b")));
    }

    @Test
    void handshakeRequiresBothSidesToAgreeOnComposedContext() throws Exception {
        // プロキシ経由などで「どのバックエンド向けか」を束縛に加える想定
        Fixtures fx = Fixtures.create();
        UUID id = UUID.randomUUID();
        byte[] serverCtx = Contexts.compose(Contexts.player(id), u("backend-1"));
        ServerHandshake server = ServerHandshake.start(
                fx.identity, fx.secrets, Fixtures.ALL_SCOPES, 0, serverCtx, Fixtures.RND);

        // 一致すれば成立
        ClientHandshake ok = ClientHandshake.accept(fx.trust, server.challenge(), serverCtx, Fixtures.RND);
        assertEquals(Fixtures.ALL_SCOPES, ok.requestedScopes());

        // 別バックエンド向けのチャレンジを流用しても通らない
        byte[] otherCtx = Contexts.compose(Contexts.player(id), u("backend-2"));
        HandshakeException e = assertThrows(
                HandshakeException.class,
                () -> ClientHandshake.accept(fx.trust, server.challenge(), otherCtx, Fixtures.RND));
        assertEquals(Reason.BAD_SIGNATURE, e.reason());

        // player 単独の束縛とも混同されない
        assertThrows(
                HandshakeException.class,
                () -> ClientHandshake.accept(fx.trust, server.challenge(), Contexts.player(id), Fixtures.RND));
    }
}
