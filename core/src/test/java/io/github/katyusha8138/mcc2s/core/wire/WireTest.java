package io.github.katyusha8138.mcc2s.core.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class WireTest {
    @Test
    void roundTrip() {
        byte[] data = new WireWriter()
                .u8(200)
                .u16(65000)
                .u32(4_000_000_000L)
                .str("こんにちは", 100)
                .blob(new byte[] {1, 2, 3}, 10)
                .fixed(new byte[] {9, 9}, 2)
                .toByteArray();
        WireReader r = new WireReader(data);
        assertEquals(200, r.u8());
        assertEquals(65000, r.u16());
        assertEquals(4_000_000_000L, r.u32());
        assertEquals("こんにちは", r.str(100));
        assertArrayEquals(new byte[] {1, 2, 3}, r.blob(10));
        assertArrayEquals(new byte[] {9, 9}, r.fixed(2));
        r.requireEnd();
    }

    @Test
    void writerRejectsOutOfRange() {
        assertThrows(WireException.class, () -> new WireWriter().u8(256));
        assertThrows(WireException.class, () -> new WireWriter().u8(-1));
        assertThrows(WireException.class, () -> new WireWriter().u16(65536));
        assertThrows(WireException.class, () -> new WireWriter().u32(-1));
        assertThrows(WireException.class, () -> new WireWriter().u32(0x1_0000_0000L));
        assertThrows(WireException.class, () -> new WireWriter().fixed(new byte[3], 4));
        assertThrows(WireException.class, () -> new WireWriter().blob(new byte[11], 10));
        assertThrows(WireException.class, () -> new WireWriter().str("abcdef", 5));
    }

    @Test
    void readerRejectsTruncation() {
        assertThrows(WireException.class, () -> new WireReader(new byte[0]).u8());
        assertThrows(WireException.class, () -> new WireReader(new byte[1]).u16());
        assertThrows(WireException.class, () -> new WireReader(new byte[3]).u32());
        assertThrows(WireException.class, () -> new WireReader(new byte[2]).fixed(3));
    }

    @Test
    void readerRejectsOversizedLengthPrefixWithoutAllocating() {
        // 長さ 4GB-1 を主張する blob。許容上限を超えるので即拒否される(巨大確保しない)
        byte[] evil = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        assertThrows(WireException.class, () -> new WireReader(evil).blob(1024));
    }

    @Test
    void readerRejectsTrailingBytes() {
        WireReader r = new WireReader(new byte[] {1, 2});
        r.u8();
        assertThrows(WireException.class, r::requireEnd);
    }

    @Test
    void readerRejectsInvalidUtf8() {
        byte[] data = new byte[] {0, 2, (byte) 0xC3, (byte) 0x28}; // 不正な 2 バイト列
        assertThrows(WireException.class, () -> new WireReader(data).str(10));
    }

    @Test
    void readerRejectsStringOverLimit() {
        byte[] data = new WireWriter().str("abcdef", 100).toByteArray();
        assertThrows(WireException.class, () -> new WireReader(data).str(5));
    }

    @Test
    void utf8LengthIsInBytes() {
        // 全角 3 文字 = 9 バイト
        String s = "あいう";
        assertEquals(9, s.getBytes(StandardCharsets.UTF_8).length);
        assertThrows(WireException.class, () -> new WireWriter().str(s, 8));
    }
}
