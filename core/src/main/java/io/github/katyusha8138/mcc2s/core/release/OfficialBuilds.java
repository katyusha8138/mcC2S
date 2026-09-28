// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.release;

import io.github.katyusha8138.mcc2s.core.crypto.Curves;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 作者のリリース鍵(Ed25519)で署名された「公式 mcC2S ビルドの SHA-256 一覧」。
 * サーバーはクライアントが報告した mcC2S 本体のハッシュをこの一覧と照合し、改造版・偽物を弾く。
 * <pre>
 * mcc2s-official-builds-v1
 * build &lt;sha256&gt; &lt;version&gt; &lt;loader&gt;
 * ...
 * signature &lt;base64url&gt;
 * </pre>
 * 署名対象は {@code signature} 行より前のテキスト全体(ラベル付き・バイト単位)。
 */
public final class OfficialBuilds {
    public static final String HEADER = "mcc2s-official-builds-v1";
    private static final String SIG_LABEL = "mcC2S/v1 official-builds\n";

    /** 公式ビルド 1 件。 */
    public record Build(String sha256, String version, String loader) {
        public Build {
            if (!Digests.isSha256Hex(sha256)) {
                throw new IllegalArgumentException("sha256 must be 64 lowercase hex chars");
            }
            if (version.isBlank() || loader.isBlank() || version.matches(".*\\s.*") || loader.matches(".*\\s.*")) {
                throw new IllegalArgumentException("version and loader must be non-empty and contain no whitespace");
            }
        }
    }

    private final List<Build> builds;
    private final Set<String> hashes;

    private OfficialBuilds(List<Build> builds) {
        this.builds = Collections.unmodifiableList(new ArrayList<>(builds));
        Set<String> h = new LinkedHashSet<>();
        for (Build b : builds) {
            h.add(b.sha256());
        }
        this.hashes = Collections.unmodifiableSet(h);
    }

    /** 掲載順のビルド一覧(追記専用で引き継ぐため、バージョン・ローダーも保持する)。 */
    public List<Build> builds() {
        return builds;
    }

    public Set<String> hashes() {
        return hashes;
    }

    public boolean contains(String sha256Hex) {
        return hashes.contains(sha256Hex);
    }

    public static OfficialBuilds empty() {
        return new OfficialBuilds(new ArrayList<>());
    }

    /** リリース公開鍵で署名を検証し、成功したものだけを返す。 */
    public static OfficialBuilds parseAndVerify(String text, byte[] releasePublicKey) throws GeneralSecurityException {
        String normalized = text.replace("\r\n", "\n");
        int sigStart = normalized.lastIndexOf("signature ");
        if (sigStart < 0 || (sigStart > 0 && normalized.charAt(sigStart - 1) != '\n')) {
            throw new GeneralSecurityException("missing signature line");
        }
        String body = normalized.substring(0, sigStart);
        String sigLine = normalized.substring(sigStart).trim();
        byte[] sig;
        try {
            sig = Base64.getUrlDecoder().decode(sigLine.substring("signature ".length()).trim());
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("signature is not valid base64url");
        }
        if (!Curves.verify(releasePublicKey, signedBytes(body), sig)) {
            throw new GeneralSecurityException("official builds signature is invalid");
        }

        String[] lines = body.split("\n");
        if (lines.length == 0 || !lines[0].trim().equals(HEADER)) {
            throw new GeneralSecurityException("bad header");
        }
        Map<String, Build> bySha = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] f = line.split("\\s+");
            if (f.length != 4 || !f[0].equals("build") || !Digests.isSha256Hex(f[1])) {
                throw new GeneralSecurityException("malformed build line: " + line);
            }
            try {
                bySha.putIfAbsent(f[1], new Build(f[1], f[2], f[3]));
            } catch (IllegalArgumentException e) {
                throw new GeneralSecurityException("malformed build line: " + line);
            }
        }
        return new OfficialBuilds(new ArrayList<>(bySha.values()));
    }

    /** ビルド一覧から署名前の本文({@link #HEADER} 行から始まる)を作る。 */
    public static String bodyOf(List<Build> builds) {
        StringBuilder sb = new StringBuilder(HEADER).append('\n');
        for (Build b : builds) {
            sb.append("build ").append(b.sha256()).append(' ').append(b.version()).append(' ').append(b.loader()).append('\n');
        }
        return sb.toString();
    }

    /** リリース担当(CI)用: 本文({@link #HEADER} 行から始まる)に署名して完全なファイル内容を返す。 */
    public static String sign(String body, Ed25519Identity releaseKey) throws GeneralSecurityException {
        String normalized = body.replace("\r\n", "\n");
        if (!normalized.startsWith(HEADER + "\n")) {
            throw new IllegalArgumentException("body must start with " + HEADER);
        }
        if (!normalized.endsWith("\n")) {
            normalized += "\n";
        }
        byte[] sig = releaseKey.sign(signedBytes(normalized));
        return normalized + "signature " + Base64.getUrlEncoder().withoutPadding().encodeToString(sig) + "\n";
    }

    private static byte[] signedBytes(String body) {
        return (SIG_LABEL + body).getBytes(StandardCharsets.UTF_8);
    }
}
