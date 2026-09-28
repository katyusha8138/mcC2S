// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import java.nio.ByteBuffer;
import java.util.UUID;

/** ハンドシェイクを特定の接続に束縛するためのコンテキスト生成。 */
public final class Contexts {
    private Contexts() {}

    /** プレイヤー UUID(16 バイト)。サーバーが確定した UUID とクライアントの自己申告が一致する接続だけが通る。 */
    public static byte[] player(UUID uuid) {
        return ByteBuffer.allocate(16)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
    }

    /**
     * 複数の束縛要素を、境界が曖昧にならないよう(個数・各長さ付きで)連結する。
     * 直結では {@link #player} だけで足りるが、プロキシ経由などで「どのバックエンド/どのプロキシ向けか」を
     * 束縛に加えたい場合の拡張点(例: {@code compose(player(uuid), utf8("lobby-1"))})。
     * サーバーとクライアントが同じ要素を同じ順序で渡さない限りハンドシェイクは成立しない。
     */
    public static byte[] compose(byte[]... parts) {
        int total = 4;
        for (byte[] p : parts) {
            total += 4 + p.length;
        }
        ByteBuffer buf = ByteBuffer.allocate(total).putInt(parts.length);
        for (byte[] p : parts) {
            buf.putInt(p.length).put(p);
        }
        return buf.array();
    }
}
