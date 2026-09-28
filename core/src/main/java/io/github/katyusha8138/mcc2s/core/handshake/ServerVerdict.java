package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.core.wire.WireReader;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;

/**
 * サーバーの判定結果(暗号化して返す)。強制力はサーバー側の切断にあり、このメッセージは
 * クライアント UI の案内と再検証間隔の通知用。
 */
public final class ServerVerdict {
    public static final int REF_ID_LEN = 8;
    public static final int MAX_MESSAGE_BYTES = 512;

    public enum Status {
        ALLOWED(0),
        DENIED(1),
        /** audit モード: 違反はあったが通した。 */
        AUDIT_ALLOWED(2);

        private final int code;

        Status(int code) {
            this.code = code;
        }

        int code() {
            return code;
        }

        static Status fromCode(int code) {
            for (Status s : values()) {
                if (s.code == code) {
                    return s;
                }
            }
            throw new WireException("unknown verdict status " + code);
        }
    }

    private final Status status;
    private final int reasonCode;
    private final byte[] refId;
    private final String message;
    private final long reverifySeconds;

    public ServerVerdict(Status status, int reasonCode, byte[] refId, String message, long reverifySeconds) {
        if (refId.length != REF_ID_LEN) {
            throw new IllegalArgumentException("refId must be " + REF_ID_LEN + " bytes");
        }
        this.status = status;
        this.reasonCode = reasonCode;
        this.refId = refId.clone();
        this.message = message;
        this.reverifySeconds = reverifySeconds;
    }

    public Status status() {
        return status;
    }

    public int reasonCode() {
        return reasonCode;
    }

    public byte[] refId() {
        return refId.clone();
    }

    /** プレイヤーに見せてよい文言(詳細は含めない)。 */
    public String message() {
        return message;
    }

    /** 次回の再検証までの秒数。0 なら再検証なし。 */
    public long reverifySeconds() {
        return reverifySeconds;
    }

    byte[] encode() {
        return new WireWriter()
                .u8(status.code())
                .u16(reasonCode)
                .fixed(refId, REF_ID_LEN)
                .str(message, MAX_MESSAGE_BYTES)
                .u32(reverifySeconds)
                .toByteArray();
    }

    static ServerVerdict decode(byte[] data) {
        WireReader r = new WireReader(data);
        Status status = Status.fromCode(r.u8());
        int reason = r.u16();
        byte[] ref = r.fixed(REF_ID_LEN);
        String msg = r.str(MAX_MESSAGE_BYTES);
        long reverify = r.u32();
        r.requireEnd();
        return new ServerVerdict(status, reason, ref, msg, reverify);
    }
}
