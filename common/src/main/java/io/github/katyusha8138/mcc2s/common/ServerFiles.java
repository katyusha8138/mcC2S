// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecrets;
import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfigException;
import io.github.katyusha8138.mcc2s.core.policy.TomlPolicyLoader;
import io.github.katyusha8138.mcc2s.core.release.OfficialBuilds;
import java.io.IOException;
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

/**
 * サーバーの {@code config/mcc2s/} を管理する。初回起動で必要なファイルをすべて生成する。
 * <pre>
 * policy.toml              ポリシー(サーバー運営者が編集)
 * server_identity.txt      サーバー識別の秘密鍵(絶対に配布しない)
 * pack_secrets.txt         pack_secret(現行 + ローテーション猶予中の旧鍵。絶対に公開しない)
 * trust/*.mc2strust        プレイヤーに配布する信頼ファイル(毎回の起動で再生成される)
 * reference/               測定証明の検証に使う参照 jar(任意)
 * official-builds.txt      署名済み公式ビルド一覧(任意)
 * </pre>
 */
public final class ServerFiles {
    public static final String POLICY = "policy.toml";
    public static final String IDENTITY = "server_identity.txt";
    public static final String SECRETS = "pack_secrets.txt";
    public static final String TRUST_DIR = "trust";
    public static final String REFERENCE_DIR = "reference";
    public static final String OFFICIAL_BUILDS = "official-builds.txt";
    private static final String SECRETS_HEADER = "mcc2s-pack-secrets-v1";
    /** 猶予中の旧鍵として残す最大数。 */
    public static final int MAX_PREVIOUS_SECRETS = 3;

    public static final class Loaded {
        private final Ed25519Identity identity;
        private final PackSecrets secrets;
        private final PolicyConfig policy;
        private final Path trustFilePath;

        Loaded(Ed25519Identity identity, PackSecrets secrets, PolicyConfig policy, Path trustFilePath) {
            this.identity = identity;
            this.secrets = secrets;
            this.policy = policy;
            this.trustFilePath = trustFilePath;
        }

        public Ed25519Identity identity() {
            return identity;
        }

        public PackSecrets secrets() {
            return secrets;
        }

        public PolicyConfig policy() {
            return policy;
        }

        /** プレイヤーへ配布する信頼ファイルの場所。 */
        public Path trustFilePath() {
            return trustFilePath;
        }
    }

    private ServerFiles() {}

    public static Loaded loadOrCreate(Path configDir, String serverLabel, Log log, SecureRandom rnd)
            throws IOException, GeneralSecurityException, PolicyConfigException {
        Files.createDirectories(configDir);
        Files.createDirectories(configDir.resolve(TRUST_DIR));
        Files.createDirectories(configDir.resolve(REFERENCE_DIR));

        Path policyPath = configDir.resolve(POLICY);
        if (!Files.exists(policyPath)) {
            writeAtomic(policyPath, TomlPolicyLoader.defaultTemplate(), false);
            log.info("[mcC2S] created " + policyPath + " (mode = enforce). Start with mode = \"audit\" if you want to review first.");
        }
        PolicyConfig policy = loadPolicy(policyPath);

        Path identityPath = configDir.resolve(IDENTITY);
        Ed25519Identity identity;
        if (Files.exists(identityPath)) {
            identity = Ed25519Identity.parse(Files.readString(identityPath, StandardCharsets.UTF_8));
        } else {
            identity = Ed25519Identity.generate(rnd);
            writeAtomic(identityPath, identity.toFileText(), true);
            log.info("[mcC2S] generated the server identity key: " + identityPath + " (keep it secret; never distribute)");
        }

        Path secretsPath = configDir.resolve(SECRETS);
        PackSecrets secrets;
        PackSecret current;
        if (Files.exists(secretsPath)) {
            List<PackSecret> parsed = parseSecrets(Files.readString(secretsPath, StandardCharsets.UTF_8));
            secrets = new PackSecrets(parsed);
            current = parsed.get(0);
        } else {
            current = PackSecret.generate(rnd);
            secrets = new PackSecrets(List.of(current));
            writeAtomic(secretsPath, secretsText(List.of(current)), true);
            log.info("[mcC2S] generated pack_secrets.txt (keep it secret)");
        }

        // 配布用の信頼ファイルは起動のたびに現行の鍵から再生成する(古いファイルが残らない)
        String keyIdHex = Digests.hex(identity.keyId());
        Path trustPath = configDir.resolve(TRUST_DIR).resolve("server-" + keyIdHex + ".mc2strust");
        writeAtomic(trustPath, new TrustFile(serverLabel, identity.publicKey(), current).toText(), false);

        return new Loaded(identity, secrets, policy, trustPath);
    }

    public static Ed25519Identity readIdentity(Path configDir) throws IOException, GeneralSecurityException {
        return Ed25519Identity.parse(Files.readString(configDir.resolve(IDENTITY), StandardCharsets.UTF_8));
    }

    /** 先頭が現行の pack_secret、以降がローテーション猶予中の旧鍵。 */
    public static List<PackSecret> readSecrets(Path configDir) throws IOException, GeneralSecurityException {
        return parseSecrets(Files.readString(configDir.resolve(SECRETS), StandardCharsets.UTF_8));
    }

    /** 配布用の信頼ファイルを書き出す(現行の pack_secret を使う)。 */
    public static Path writeTrustFile(Path configDir, String label, Ed25519Identity identity, PackSecret current) throws IOException {
        Files.createDirectories(configDir.resolve(TRUST_DIR));
        Path path = configDir.resolve(TRUST_DIR).resolve("server-" + Digests.hex(identity.keyId()) + ".mc2strust");
        writeAtomic(path, new TrustFile(label, identity.publicKey(), current).toText(), false);
        return path;
    }

    /**
     * pack_secret のローテーション: 新しい秘密を現行にし、これまでの現行を猶予中の旧鍵に移す(最大 {@link #MAX_PREVIOUS_SECRETS} 個)。
     * 旧鍵の信頼ファイルを持つプレイヤーも、旧鍵を削除するまでは参加できる。新しい信頼ファイルを再生成して返す。
     */
    public static Path rotateSecret(Path configDir, String label, SecureRandom rnd) throws IOException, GeneralSecurityException {
        Ed25519Identity identity = readIdentity(configDir);
        List<PackSecret> old = readSecrets(configDir);
        PackSecret fresh = PackSecret.generate(rnd);
        List<PackSecret> next = new ArrayList<>();
        next.add(fresh);
        next.addAll(old.subList(0, Math.min(old.size(), MAX_PREVIOUS_SECRETS)));
        writeAtomic(configDir.resolve(SECRETS), secretsText(next), true);
        return writeTrustFile(configDir, label, identity, fresh);
    }

    public static PolicyConfig loadPolicy(Path policyPath) throws IOException, PolicyConfigException {
        return TomlPolicyLoader.parse(Files.readString(policyPath, StandardCharsets.UTF_8));
    }

    /** 公式ビルド一覧。リリース鍵が未設定、またはファイルが無い場合は空(=サーバー自身と同一ビルドのみ許可)。 */
    public static OfficialBuilds loadOfficialBuilds(Path configDir, Log log) {
        Optional<byte[]> key = ReleaseKey.publicKey();
        Path file = configDir.resolve(OFFICIAL_BUILDS);
        if (key.isEmpty()) {
            log.info("[mcC2S] no release key is embedded in this build; only clients running the exact same mcC2S build as this server are allowed");
            return OfficialBuilds.empty();
        }
        if (!Files.exists(file)) {
            log.info("[mcC2S] " + OFFICIAL_BUILDS + " not found; only clients running the same mcC2S build as this server are allowed");
            return OfficialBuilds.empty();
        }
        try {
            return OfficialBuilds.parseAndVerify(Files.readString(file, StandardCharsets.UTF_8), key.get());
        } catch (IOException | GeneralSecurityException e) {
            log.error("[mcC2S] ignoring " + file + ": " + e.getMessage(), null);
            return OfficialBuilds.empty();
        }
    }

    // ---- pack_secrets.txt ----

    static String secretsText(List<PackSecret> secrets) {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        StringBuilder sb = new StringBuilder(SECRETS_HEADER).append('\n');
        sb.append("# current: 新しい信頼ファイルに入る鍵。previous: ローテーション猶予中の旧鍵(旧信頼ファイルのプレイヤーも受理)\n");
        sb.append("current = ").append(enc.encodeToString(secrets.get(0).value())).append('\n');
        for (int i = 1; i < secrets.size(); i++) {
            sb.append("previous = ").append(enc.encodeToString(secrets.get(i).value())).append('\n');
        }
        return sb.toString();
    }

    static List<PackSecret> parseSecrets(String text) throws GeneralSecurityException {
        String[] lines = text.replace("\r\n", "\n").split("\n");
        int i = 0;
        while (i < lines.length && (lines[i].isBlank() || lines[i].trim().startsWith("#"))) {
            i++;
        }
        if (i >= lines.length || !lines[i].trim().equals(SECRETS_HEADER)) {
            throw new GeneralSecurityException("bad pack_secrets.txt header");
        }
        PackSecret current = null;
        List<PackSecret> previous = new ArrayList<>();
        for (i++; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new GeneralSecurityException("malformed line in pack_secrets.txt");
            }
            String key = line.substring(0, eq).trim();
            PackSecret secret;
            try {
                secret = new PackSecret(Base64.getUrlDecoder().decode(line.substring(eq + 1).trim()));
            } catch (IllegalArgumentException e) {
                throw new GeneralSecurityException("invalid secret value for " + key);
            }
            if (key.equals("current")) {
                if (current != null) {
                    throw new GeneralSecurityException("duplicate 'current' in pack_secrets.txt");
                }
                current = secret;
            } else if (key.equals("previous")) {
                previous.add(secret);
            } else {
                throw new GeneralSecurityException("unknown key '" + key + "' in pack_secrets.txt");
            }
        }
        if (current == null) {
            throw new GeneralSecurityException("pack_secrets.txt has no 'current'");
        }
        List<PackSecret> all = new ArrayList<>();
        all.add(current);
        all.addAll(previous);
        return all;
    }

    // ---- 書き込み ----

    private static void writeAtomic(Path target, String content, boolean secret) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        if (secret) {
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException | IOException e) {
                // POSIX 以外(Windows 等)では設定できない。ユーザーフォルダの ACL に任せる
            }
        }
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
