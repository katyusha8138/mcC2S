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
}
