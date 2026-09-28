// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.cli;

import io.github.katyusha8138.mcc2s.common.EntryKindNames;
import io.github.katyusha8138.mcc2s.common.HashCache;
import io.github.katyusha8138.mcc2s.common.PolicyEditor;
import io.github.katyusha8138.mcc2s.common.ServerFiles;
import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.release.OfficialBuilds;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** 各コマンドの実装。 */
final class Commands {
    private static final SecureRandom RANDOM = new SecureRandom();

    private Commands() {}

    // ---- hash ----

    static int hash(List<String> rest, PrintStream out, PrintStream err) throws IOException {
        Args a = Args.parse(rest, Set.of("kind", "id", "version"), Set.of("toml"));
        if (a.positional.isEmpty()) {
            throw new Args.UsageException("hash needs at least one path");
        }
        if ((a.values.containsKey("id") || a.values.containsKey("version")) && a.positional.size() != 1) {
            throw new Args.UsageException("--id / --version can only be used with a single path");
        }
        EntryKind kind = parseKind(a.get("kind", "mod"));
        HashCache cache = new HashCache();
        int status = 0;
        for (String p : a.positional) {
            Path path = Path.of(p);
            if (!Files.exists(path)) {
                err.println("見つかりません: " + p);
                status = 1;
                continue;
            }
            String sha = cache.sha256(path);
            if (!a.has("toml")) {
                out.println(sha + "  " + p);
                continue;
            }
            String id = a.values.get("id");
            String version = a.values.get("version");
            if (id == null || version == null) {
                Optional<JarInfo.Info> info = Files.isRegularFile(path) ? JarInfo.read(path) : Optional.empty();
                if (id == null) {
                    id = info.map(JarInfo.Info::modId).orElse(kind == EntryKind.MOD ? stem(path) : path.getFileName().toString());
                }
                if (version == null) {
                    version = info.map(JarInfo.Info::version).orElse("");
                }
            }
            out.print(PolicyEditor.snippet(kind, id, version, sha, "mcc2s-cli hash: " + path.getFileName()));
            out.println();
        }
        return status;
    }

    private static EntryKind parseKind(String s) {
        try {
            return EntryKindNames.parse(s);
        } catch (IllegalArgumentException e) {
            throw new Args.UsageException(e.getMessage());
        }
    }

    private static String stem(Path p) {
        String n = p.getFileName().toString();
        int dot = n.lastIndexOf('.');
        return dot > 0 ? n.substring(0, dot) : n;
    }

    // ---- keygen / pubkey ----

    static int keygen(List<String> rest, PrintStream out, PrintStream err) throws IOException, GeneralSecurityException {
        Args a = Args.parse(rest, Set.of("out"), Set.of("force"));
        Path target = Path.of(a.require("out"));
        if (Files.exists(target) && !a.has("force")) {
            err.println("すでに存在します: " + target + "(上書きするには --force。既存の鍵を失うと過去の署名を再現できません)");
            return 1;
        }
        Ed25519Identity id = Ed25519Identity.generate(RANDOM);
        writePrivate(target, id.toFileText());
        out.println("リリース署名鍵を生成しました: " + target);
        out.println("公開鍵(base64url): " + b64(id.publicKey()));
        out.println("鍵 ID: " + Digests.hex(id.keyId()));
        out.println();
        out.println("次の手順:");
        out.println("  1. 公開鍵を release/release-public-key.txt に保存してコミットする(公開情報)");
        out.println("  2. " + target + " の中身を GitHub Actions のシークレット MCC2S_RELEASE_KEY に登録し、ファイル自体は安全な場所に保管する");
        out.println("  3. 秘密鍵ファイルはコミット・チャット・メールに載せない");
        return 0;
    }

    static int pubkey(List<String> rest, PrintStream out, PrintStream err) throws IOException, GeneralSecurityException {
        Args a = Args.parse(rest, Set.of("identity"), Set.of());
        Ed25519Identity id = Ed25519Identity.parse(Files.readString(Path.of(a.require("identity")), StandardCharsets.UTF_8));
        out.println(b64(id.publicKey()));
        return 0;
    }

    // ---- trustfile / rotate-secret ----

    static int trustfile(List<String> rest, PrintStream out, PrintStream err) throws IOException, GeneralSecurityException {
        Args a = Args.parse(rest, Set.of("config", "label", "out"), Set.of());
        Path config = Path.of(a.require("config"));
        Ed25519Identity identity = ServerFiles.readIdentity(config);
        PackSecret current = ServerFiles.readSecrets(config).get(0);
        String label = a.get("label", "mcC2S server");
        if (a.values.containsKey("out")) {
            Path target = Path.of(a.values.get("out"));
            Files.writeString(target, new TrustFile(label, identity.publicKey(), current).toText(), StandardCharsets.UTF_8);
            out.println("信頼ファイルを書き出しました: " + target);
        } else {
            out.println("信頼ファイルを書き出しました: " + ServerFiles.writeTrustFile(config, label, identity, current));
        }
        out.println("プレイヤーの config/mcc2s/trust/ に置いてもらってください(秘密鍵は含まれません)。");
        return 0;
    }

    static int rotateSecret(List<String> rest, PrintStream out, PrintStream err) throws IOException, GeneralSecurityException {
        Args a = Args.parse(rest, Set.of("config", "label"), Set.of());
        Path config = Path.of(a.require("config"));
        Path trust = ServerFiles.rotateSecret(config, a.get("label", "mcC2S server"), RANDOM);
        out.println("pack_secret をローテーションしました。新しい信頼ファイル: " + trust);
        out.println("- 旧鍵は猶予として pack_secrets.txt に残っています(旧信頼ファイルのプレイヤーも参加できます)");
        out.println("- 新しい信頼ファイルを配布し、全員が更新したら、pack_secrets.txt の previous 行を削除して /mcc2s reload してください");
        return 0;
    }

    // ---- sign-release / verify-release ----

    static int signRelease(List<String> rest, PrintStream out, PrintStream err) throws IOException, GeneralSecurityException {
        Args a = Args.parse(rest, Set.of("key", "version", "loader", "base", "out"), Set.of());
        if (a.positional.isEmpty()) {
            throw new Args.UsageException("sign-release needs at least one jar");
        }
        Ed25519Identity key = Ed25519Identity.parse(Files.readString(Path.of(a.require("key")), StandardCharsets.UTF_8));
        String version = a.require("version");
        String loader = a.require("loader");

        List<OfficialBuilds.Build> builds = new ArrayList<>();
        if (a.values.containsKey("base")) {
            // 引き継ぐ一覧は、同じ鍵の署名が付いていることを必ず検証する(改ざんされた一覧を再署名しない)
            OfficialBuilds base = OfficialBuilds.parseAndVerify(
                    Files.readString(Path.of(a.values.get("base")), StandardCharsets.UTF_8), key.publicKey());
            builds.addAll(base.builds());
        }
        for (String jar : a.positional) {
            Path path = Path.of(jar);
            if (!Files.isRegularFile(path)) {
                throw new IOException("jar が見つかりません: " + jar);
            }
            String sha = Digests.hex(Digests.sha256(path));
            if (builds.stream().noneMatch(b -> b.sha256().equals(sha))) {
                builds.add(new OfficialBuilds.Build(sha, version, loader));
                out.println("追加: " + sha + "  " + version + "  " + loader + "  (" + path.getFileName() + ")");
            } else {
                out.println("すでに掲載済み: " + sha + "  (" + path.getFileName() + ")");
            }
        }
        String signed = OfficialBuilds.sign(OfficialBuilds.bodyOf(builds), key);
        Path target = Path.of(a.get("out", "official-builds.txt"));
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.writeString(tmp, signed, StandardCharsets.UTF_8);
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        out.println("署名済みの公式ビルド一覧を書き出しました: " + target + "(" + builds.size() + " 件)");
        return 0;
    }

    static int verifyRelease(List<String> rest, PrintStream out, PrintStream err) throws IOException {
        Args a = Args.parse(rest, Set.of("pubkey"), Set.of());
        if (a.positional.size() != 1) {
            throw new Args.UsageException("verify-release needs exactly one file");
        }
        byte[] pub = readPublicKey(a.require("pubkey"));
        try {
            OfficialBuilds ob = OfficialBuilds.parseAndVerify(Files.readString(Path.of(a.positional.get(0)), StandardCharsets.UTF_8), pub);
            out.println("署名は正しいです。公式ビルド " + ob.builds().size() + " 件:");
            for (OfficialBuilds.Build b : ob.builds()) {
                out.println("  " + b.sha256() + "  " + b.version() + "  " + b.loader());
            }
            return 0;
        } catch (GeneralSecurityException e) {
            err.println("検証に失敗しました: " + e.getMessage());
            return 1;
        }
    }

    private static byte[] readPublicKey(String arg) throws IOException {
        Path p = Path.of(arg);
        String text = Files.isRegularFile(p) ? Files.readString(p, StandardCharsets.UTF_8).trim() : arg.trim();
        try {
            byte[] raw = Base64.getUrlDecoder().decode(text);
            if (raw.length != 32) {
                throw new IOException("公開鍵は 32 バイト(base64url)である必要があります");
            }
            return raw;
        } catch (IllegalArgumentException e) {
            throw new IOException("公開鍵が base64url として不正です");
        }
    }

    // ---- 共通 ----

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** 秘密鍵ファイルの書き込み(可能なら所有者のみ読み書き)。 */
    private static void writePrivate(Path target, String content) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            // POSIX 以外では設定できない
        }
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
    }
}
