// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import java.util.Base64;
import java.util.Optional;

/**
 * mcC2S 公式ビルド一覧の署名を検証するリリース公開鍵(Ed25519, base64url)。
 * <p>
 * まだ発行されていない場合は空文字のままにする。その場合サーバーは「サーバー自身と同一ビルドの
 * mcC2S を持つクライアントのみ許可」という最も厳格な動作になる(安全側)。
 * リリース鍵を生成したら、ここに公開鍵を埋め込み、{@code official-builds.txt} を署名して配布する。
 */
public final class ReleaseKey {
    /** TODO(リリース担当): 鍵生成後に公開鍵をここへ設定する。 */
    public static final String PUBLIC_KEY_BASE64URL = "";

    private ReleaseKey() {}

    public static Optional<byte[]> publicKey() {
        if (PUBLIC_KEY_BASE64URL.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(Base64.getUrlDecoder().decode(PUBLIC_KEY_BASE64URL));
    }
}
