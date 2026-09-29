// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.obfuscator;

import java.nio.charset.StandardCharsets;

/**
 * 難読化した文字列を元に戻す処理の雛形。このクラスは配布物には入らない。
 * {@link StringObfuscator} が、このクラスの {@code decode} のバイトコードを、文字列を持つ各クラスへ
 * private static synthetic メソッドとして複製する(専用の共有クラスを作ると、そこ 1 か所を見張るだけで
 * 全文字列が読めてしまうため)。
 *
 * <p>複製できるよう、JDK のクラス以外を参照せず、このクラス自身の静的メンバも使わない。
 * 鍵は文字列ごとに異なる 64 ビット値で、xorshift64 の鍵ストリームを XOR する。
 * これは秘匿ではなく、文字列定数から動作を推測される手間を増やすための難読化にすぎない。
 */
final class Decoder {
    private Decoder() {}

    static String decode(String s, long key) {
        long x = key;
        byte[] b = new byte[s.length()];
        for (int i = 0; i < b.length; i++) {
            x ^= x << 13;
            x ^= x >>> 7;
            x ^= x << 17;
            b[i] = (byte) (s.charAt(i) ^ (int) x);
        }
        return new String(b, StandardCharsets.UTF_8);
    }
}
