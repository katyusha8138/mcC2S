package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.core.wire.WireReader;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Minecraft のカスタムペイロード(サーバー行き約 32KB)に収めるための分割。
 * 数百 Mod のマニフェストは 1 パケットに収まらないため、チャンクに分けて順序通りに送る。
 */
public final class Fragmenter {
    public static final int TYPE_CHALLENGE = 1;
    public static final int TYPE_ATTESTATION = 2;
    public static final int TYPE_VERDICT = 3;

    /** チャンクのヘッダ分(type 1 + index 2 + total 2 + 長さ 4)。 */
    public static final int HEADER_BYTES = 9;
    /** デコード時に受け付けるチャンク本体の上限。 */
    public static final int MAX_CHUNK_DATA = 1024 * 1024;

    private Fragmenter() {}

    public static final class Chunk {
        private final int type;
        private final int index;
        private final int total;
        private final byte[] data;

        public Chunk(int type, int index, int total, byte[] data) {
            this.type = type;
            this.index = index;
            this.total = total;
            this.data = data.clone();
        }

        public int type() {
            return type;
        }

        public int index() {
            return index;
        }

        public int total() {
            return total;
        }

        public byte[] data() {
            return data.clone();
        }

        public byte[] encode() {
            return new WireWriter().u8(type).u16(index).u16(total).blob(data, MAX_CHUNK_DATA).toByteArray();
        }

        public static Chunk decode(byte[] bytes) {
            WireReader r = new WireReader(bytes);
            int type = r.u8();
            int index = r.u16();
            int total = r.u16();
            byte[] data = r.blob(MAX_CHUNK_DATA);
            r.requireEnd();
            return new Chunk(type, index, total, data);
        }
    }

    /** {@code maxChunkData} バイト以下のチャンク列に分割する(空メッセージも 1 チャンクになる)。 */
    public static List<Chunk> split(int type, byte[] message, int maxChunkData) {
        if (maxChunkData <= 0 || maxChunkData > MAX_CHUNK_DATA) {
            throw new IllegalArgumentException("bad maxChunkData");
        }
        int total = Math.max(1, (message.length + maxChunkData - 1) / maxChunkData);
        if (total > 0xFFFF) {
            throw new WireException("message needs too many chunks");
        }
        List<Chunk> out = new ArrayList<>(total);
        for (int i = 0; i < total; i++) {
            int from = i * maxChunkData;
            int to = Math.min(message.length, from + maxChunkData);
            out.add(new Chunk(type, i, total, Arrays.copyOfRange(message, from, to)));
        }
        return out;
    }
}
