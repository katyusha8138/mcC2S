package io.github.katyusha8138.mcc2s.core.wire;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** {@link WireWriter} の対。未信頼入力を想定し、上限超過・切り詰め・不正 UTF-8 を厳格に拒否する。 */
public final class WireReader {
    private final byte[] data;
    private int pos;

    public WireReader(byte[] data) {
        this.data = data;
    }

    public int remaining() {
        return data.length - pos;
    }

    private void need(long n) {
        if (n < 0 || n > remaining()) {
            throw new WireException("truncated input");
        }
    }

    public int u8() {
        need(1);
        return data[pos++] & 0xFF;
    }

    public int u16() {
        need(2);
        int v = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    public long u32() {
        need(4);
        long v = ((long) (data[pos] & 0xFF) << 24)
                | ((long) (data[pos + 1] & 0xFF) << 16)
                | ((long) (data[pos + 2] & 0xFF) << 8)
                | (long) (data[pos + 3] & 0xFF);
        pos += 4;
        return v;
    }

    public byte[] fixed(int len) {
        need(len);
        byte[] b = Arrays.copyOfRange(data, pos, pos + len);
        pos += len;
        return b;
    }

    public byte[] blob(int max) {
        long len = u32();
        if (len > max) {
            throw new WireException("blob too large: " + len + " > " + max);
        }
        return fixed((int) len);
    }

    public String str(int maxBytes) {
        int len = u16();
        if (len > maxBytes) {
            throw new WireException("string too long: " + len + " > " + maxBytes);
        }
        byte[] b = fixed(len);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(b))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new WireException("invalid UTF-8");
        }
    }

    /** 末尾に余剰バイトがあれば拒否する(曖昧なパースの排除)。 */
    public void requireEnd() {
        if (remaining() != 0) {
            throw new WireException("trailing bytes: " + remaining());
        }
    }
}
