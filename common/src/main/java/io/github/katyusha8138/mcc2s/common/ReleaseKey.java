// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * mcC2S 公式ビルド一覧の署名を検証するリリース公開鍵(Ed25519, base64url)。
 * <p>
 * ビルド時に、リポジトリの {@code release/release-public-key.txt} が jar 内のリソースとして同梱される
 * (Gradle の processResources)。ファイルが無いビルドでは鍵なし = 「サーバー自身と同一ビルドの
 * mcC2S を持つクライアントのみ許可」という最も厳格な動作になる(安全側)。
 * 鍵を生成したら {@code mcc2s-cli keygen} → 公開鍵を上記ファイルに保存する(docs/RELEASING.md)。
 */
public final class ReleaseKey {
    static final String RESOURCE = "/io/github/katyusha8138/mcc2s/common/release-public-key.txt";

    private ReleaseKey() {}

    public static Optional<byte[]> publicKey() {
        try (InputStream in = ReleaseKey.class.getResourceAsStream(RESOURCE)) {
            return parse(in);
        } catch (IOException e) {
            throw new IllegalStateException("could not read the embedded release key", e);
        }
    }

    /** @param in null(リソース無し)なら空。壊れた内容は例外(ビルドの不具合を黙って見逃さない)。 */
    static Optional<byte[]> parse(InputStream in) throws IOException {
        if (in == null) {
            return Optional.empty();
        }
        String text = new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        if (text.isEmpty()) {
            return Optional.empty();
        }
        try {
            byte[] raw = Base64.getUrlDecoder().decode(text);
            if (raw.length != 32) {
                throw new IllegalStateException("the embedded release key must be 32 bytes, got " + raw.length);
            }
            return Optional.of(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("the embedded release key is not valid base64url");
        }
    }
}
