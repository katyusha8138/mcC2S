// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * サーバー運営者が生成し、Mod パックに同梱してプレイヤーへ配布する「信頼ファイル」。
 * サーバー識別公開鍵(なりすまし防止のピン留め)と pack_secret(クライアント認証)を含む。
 */
public final class TrustFile {
    public static final String HEADER = "mcc2s-trust-v1";
    public static final int MAX_LABEL_CHARS = 64;

    private final String label;
    private final byte[] serverPublicKey;
    private final PackSecret packSecret;

    public TrustFile(String label, byte[] serverPublicKey, PackSecret packSecret) {
        if (label.length() > MAX_LABEL_CHARS || label.indexOf('\n') >= 0 || label.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("bad label");
        }
        if (serverPublicKey.length != Curves.KEY_LEN) {
            throw new IllegalArgumentException("bad server public key");
        }
        this.label = label;
        this.serverPublicKey = serverPublicKey.clone();
        this.packSecret = packSecret;
    }

    public String label() {
        return label;
    }

    public byte[] serverPublicKey() {
        return serverPublicKey.clone();
    }

    public byte[] serverKeyId() {
        return Ed25519Identity.keyId(serverPublicKey);
    }

    public PackSecret packSecret() {
        return packSecret;
    }

    private byte[] checksum() {
        return Arrays.copyOf(Digests.framed("mcC2S/v1 trust-check", label.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                serverPublicKey, packSecret.value()), 4);
    }

    public String toText() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return HEADER + "\n"
                + "# このファイルは pack_secret を含みます。プレイヤーには配布して構いませんが、公開掲示板等には載せないでください。\n"
                + "label = " + label + "\n"
                + "server_key = " + enc.encodeToString(serverPublicKey) + "\n"
                + "pack_secret = " + enc.encodeToString(packSecret.value()) + "\n"
                + "check = " + enc.encodeToString(checksum()) + "\n";
    }

    /** コピー&ペーストの欠落を検出するチェックサム付きで検証しながら読む。 */
    public static TrustFile parse(String text) throws GeneralSecurityException {
        KeyValueText kv = KeyValueText.parse(text, HEADER);
        TrustFile tf = new TrustFile(
                kv.stringOr("label", ""),
                kv.base64("server_key", Curves.KEY_LEN),
                new PackSecret(kv.base64("pack_secret", PackSecret.LEN)));
        if (!Digests.equal(tf.checksum(), kv.base64("check", 4))) {
            throw new GeneralSecurityException("trust file checksum mismatch (file is corrupted or edited)");
        }
        return tf;
    }
}
