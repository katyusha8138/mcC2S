// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.wire.WireException;
import java.io.ByteArrayOutputStream;
import java.util.Optional;

/**
 * 1 方向・1 メッセージ分のチャンク再組み立て。順序保証(TCP)を前提に、順序外・重複・
 * 種別違い・総量超過・完了後の追加をすべてエラーとして拒否する。
 */
public final class Reassembler {
    private final int type;
    private final int maxTotalBytes;
    private final int maxChunks;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int total = -1;
    private int next;
    private boolean done;

    public Reassembler(int type, int maxTotalBytes, int maxChunks) {
        this.type = type;
        this.maxTotalBytes = maxTotalBytes;
        this.maxChunks = maxChunks;
    }

    /** 全チャンクが揃ったときだけメッセージ全体を返す。 */
    public Optional<byte[]> accept(Fragmenter.Chunk chunk) {
        if (done) {
            throw new WireException("chunk after completion");
        }
        if (chunk.type() != type) {
            throw new WireException("unexpected chunk type " + chunk.type());
        }
        if (total < 0) {
            if (chunk.total() < 1 || chunk.total() > maxChunks) {
                throw new WireException("bad chunk count " + chunk.total());
            }
            total = chunk.total();
        } else if (chunk.total() != total) {
            throw new WireException("chunk count changed");
        }
        if (chunk.index() != next) {
            throw new WireException("out-of-order chunk " + chunk.index() + " (expected " + next + ")");
        }
        byte[] data = chunk.data();
        if ((long) buffer.size() + data.length > maxTotalBytes) {
            throw new WireException("message too large");
        }
        buffer.write(data, 0, data.length);
        next++;
        if (next == total) {
            done = true;
            return Optional.of(buffer.toByteArray());
        }
        return Optional.empty();
    }
}
