// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.wire;

/** ワイヤーフォーマットの構文エラー(長さ超過・切り詰め・不正な文字など)。 */
public final class WireException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public WireException(String message) {
        super(message);
    }
}
