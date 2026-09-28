// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * サーバー別の共有秘密(256bit)。サーバーが生成し、信頼ファイルに入れて Mod パックと一緒に配布する。
 * <p>
 * 注意: 正規プレイヤーは全員この値を持つ。目的は「そのサーバーの信頼ファイルを持たない第三者の
 * 偽クライアント/汎用バイパス」を弾くことで、正規プレイヤー自身による抽出は防げない。
 */
public final class PackSecret {
    public static final int LEN = 32;
    public static final int ID_LEN = 8;

    private final byte[] value;

    public PackSecret(byte[] value) {
        if (value == null || value.length != LEN) {
            throw new IllegalArgumentException("pack secret must be " + LEN + " bytes");
        }
        this.value = value.clone();
    }

    public static PackSecret generate(SecureRandom rnd) {
        byte[] b = new byte[LEN];
        rnd.nextBytes(b);
        return new PackSecret(b);
    }

    public byte[] value() {
        return value.clone();
    }

    /** 秘密そのものを漏らさない短い識別子(ローテーション時の鍵選択用)。 */
    public byte[] id() {
        return id(value);
    }

    static byte[] id(byte[] secret) {
        return Arrays.copyOf(Digests.hmac(secret, Labels.SECRET_ID.getBytes(java.nio.charset.StandardCharsets.UTF_8)), ID_LEN);
    }
}
