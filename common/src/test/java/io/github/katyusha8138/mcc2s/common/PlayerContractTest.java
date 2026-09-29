// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * 検証対象のプレイヤーは 3 項目とも必須。Forge 1.20.1 のオフラインモードでは、ログイン交渉の時点で UUID が無く、
 * null のまま違反記録の作成まで進んで NPE になり(判定は安全側に倒れたが)「予期しないエラー」で切断されていた。
 * 境界で早く・分かりやすく失敗させる。
 */
class PlayerContractTest {
    @Test
    void everyFieldIsRequired() {
        UUID id = UUID.randomUUID();
        assertThrows(NullPointerException.class, () -> new ServerVerification.Player(null, id, "127.0.0.1:1"));
        assertThrows(NullPointerException.class, () -> new ServerVerification.Player("Alex", null, "127.0.0.1:1"));
        assertThrows(NullPointerException.class, () -> new ServerVerification.Player("Alex", id, null));
    }

    @Test
    void anOrdinaryPlayerIsAccepted() {
        UUID id = UUID.randomUUID();
        ServerVerification.Player p = new ServerVerification.Player("Alex", id, "127.0.0.1:1");
        assertEquals("Alex", p.name());
        assertEquals(id, p.id());
        assertEquals("127.0.0.1:1", p.address());
    }
}
