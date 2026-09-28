// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

/** ファイル名など、外部由来の文字列をマニフェストの制約(制御文字なし・長さ上限)に合わせる。 */
public final class Sanitize {
    private Sanitize() {}

    /** 制御文字を '?' に置換し、最大 {@code maxChars} 文字に切り詰める。 */
    public static String text(String s, int maxChars) {
        StringBuilder sb = new StringBuilder(Math.min(s.length(), maxChars));
        for (int i = 0; i < s.length() && sb.length() < maxChars; i++) {
            char c = s.charAt(i);
            boolean control = c < 0x20 || c == 0x7F || (c >= 0x80 && c < 0xA0) || c == ' ' || c == ' ';
            sb.append(control ? '?' : c);
        }
        return sb.toString();
    }
}
