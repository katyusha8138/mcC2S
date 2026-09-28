// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.handshake.Contexts;
import java.nio.charset.StandardCharsets;

/**
 * ハンドシェイクの接続束縛(context)の作り方。サーバーとクライアントで完全に一致させる必要がある。
 * <p>
 * プレイヤー名を使う理由: オフラインモードのサーバーでは、サーバーが割り当てる UUID(名前由来)と
 * クライアントが持つ UUID が一致しないため、UUID では束縛できない。ログイン名は両側が必ず知っている。
 * 将来プロキシ等に対応する場合は {@link Contexts#compose} で要素を追加する(docs/PROXY.md)。
 */
public final class Bindings {
    private Bindings() {}

    public static byte[] player(String loginName) {
        return Contexts.compose("mcC2S/player-name".getBytes(StandardCharsets.UTF_8), loginName.getBytes(StandardCharsets.UTF_8));
    }
}
