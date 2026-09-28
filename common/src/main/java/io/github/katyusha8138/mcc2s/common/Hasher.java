// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import java.io.IOException;
import java.nio.file.Path;

/** ファイル/フォルダの SHA-256(小文字 16 進)を返す。通常は {@link HashCache}。 */
@FunctionalInterface
public interface Hasher {
    String sha256(Path path) throws IOException;
}
