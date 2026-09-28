// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecret;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecrets;
import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.handshake.TrustStore;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/**
 * サーバーとクライアントの検証をメモリ内で接続するテスト用ハーネス。
 * 送信されるチャンクは、Minecraft の実際の上限(約 32KB)を超えていないか毎回検査する。
 */
final class Harness {
    static final SecureRandom RND = new SecureRandom();
    static final int MAX_SERVERBOUND_PAYLOAD = 32_767;

    final Path serverDir;
    final Path clientDir;
    final Ed25519Identity identity;
    final PackSecret secret;
    final HashCache cache = new HashCache();
    final List<ViolationReport> reports = new ArrayList<>();
    final List<String> logLines = new ArrayList<>();
    final Log log = new Log() {
        @Override
        public void info(String message) {
            logLines.add("INFO " + message);
        }

        @Override
        public void warn(String message) {
            logLines.add("WARN " + message);
        }

        @Override
        public void error(String message, Throwable cause) {
            logLines.add("ERROR " + message + (cause == null ? "" : " " + cause));
        }
    };

    final ViolationLog violationLog;
    Executor serverWorker = Runnable::run;
    Executor clientWorker = Runnable::run;
    PolicyConfig policy = PolicyConfig.defaults();
    List<EntrySeed> serverOwn = new ArrayList<>();
    ReferenceIndex references;
    /** 直近の connect で使われたサーバー側コンテキスト(統計の確認用)。 */
    ServerContext lastContext;
    /** true なら ServerVerification を再検証モードで作る。 */
    boolean recheck;
    io.github.katyusha8138.mcc2s.core.policy.ReferenceResolver referencesOverride;
    String serverSelfSha;
    TrustStore clientTrust;

    Harness(Path base) throws IOException, GeneralSecurityException {
        serverDir = Files.createDirectories(base.resolve("server"));
        clientDir = Files.createDirectories(base.resolve("client"));
        violationLog = new ViolationLog(base.resolve("logs/violations.jsonl"), log);
        identity = Ed25519Identity.generate(RND);
        secret = PackSecret.generate(RND);
        clientTrust = new TrustStore(List.of(new TrustFile("test", identity.publicKey(), secret)));
    }

    static String sha(String seed) {
        return io.github.katyusha8138.mcc2s.core.crypto.Digests.hex(
                io.github.katyusha8138.mcc2s.core.crypto.Digests.sha256(seed.getBytes(StandardCharsets.UTF_8)));
    }

    Path file(Path dir, String name, String content) throws IOException {
        Path p = dir.resolve(name);
        Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }

    EntrySeed seed(EntryKind kind, String id, String version, Path file) throws IOException {
        return new EntrySeed(kind, id, version, cache.sha256(file), file);
    }

    /** サーバーが持つ mcC2S 本体。クライアントも同じバイト列の jar を持つ。 */
    EntrySeed selfSeed(Path dir) throws IOException {
        Path p = dir.resolve("mcc2s.jar");
        if (!Files.exists(p)) {
            Files.writeString(p, "official mcC2S build", StandardCharsets.UTF_8);
        }
        return new EntrySeed(EntryKind.SELF, "mcc2s", "0.1.0", cache.sha256(p), p);
    }

    ServerContext serverContext() throws IOException {
        EntrySeed self = selfSeed(serverDir);
        serverSelfSha = self.sha256();
        List<Entry> baseline = new ArrayList<>();
        for (EntrySeed s : serverOwn) {
            baseline.add(s.toEntry());
        }
        List<EntrySeed> refSrc = new ArrayList<>(serverOwn);
        refSrc.add(self);
        references = ReferenceIndex.build(refSrc, null, cache, log);
        return ServerContext.builder()
                .identity(identity)
                .secrets(new PackSecrets(List.of(secret)))
                .policy(policy)
                .baseline(baseline)
                .trustedSelfHashes(java.util.Set.of(self.sha256()))
                .references(referencesOverride != null ? referencesOverride : references)
                .sink(report -> {
                    reports.add(report);
                    violationLog.report(report);
                })
                .log(log)
                .random(RND)
                .worker(serverWorker)
                .build();
    }

    /** 1 回の接続の結果。 */
    static final class Outcome {
        final List<String> kicks = new ArrayList<>();
        final List<String> aborts = new ArrayList<>();
        boolean allowed;
        int serverToClientChunks;
        int clientToServerChunks;
        int largestClientChunk;
        ClientVerification client;
        ServerVerification server;

        boolean kicked() {
            return !kicks.isEmpty();
        }
    }

    /** クライアントが集める項目。 */
    interface Seeds {
        List<EntrySeed> get() throws Exception;
    }

    Outcome connect(String playerName, Seeds clientSeeds) throws Exception {
        return connect(playerName, clientSeeds, () -> clientTrust, EnumSet.allOf(Scope.class));
    }

    Outcome connect(String playerName, Seeds clientSeeds, Supplier<TrustStore> trust, java.util.Set<Scope> reported)
            throws Exception {
        ServerContext ctx = serverContext();
        lastContext = ctx;
        Outcome out = new Outcome();
        Deque<byte[]> toClient = new ArrayDeque<>();
        Deque<byte[]> toServer = new ArrayDeque<>();

        ServerVerification server = new ServerVerification(
                ctx,
                new ServerVerification.Player(playerName, UUID.randomUUID(), "127.0.0.1:12345"),
                new ServerVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {
                        toClient.add(chunk);
                        out.serverToClientChunks++;
                    }

                    @Override
                    public void kick(String message) {
                        out.kicks.add(message);
                    }

                    @Override
                    public void allow() {
                        out.allowed = true;
                    }
                },
                recheck);

        ClientVerification client = new ClientVerification(
                trust,
                Bindings.player(playerName),
                requested -> new ClientVerification.Collected(reported, clientSeeds.get()),
                new ManifestAssembler.Env("1.21.1", "neoforge", "21.1.0", "0.1.0"),
                new ClientVerification.Transport() {
                    @Override
                    public void send(byte[] chunk) {
                        if (chunk.length > MAX_SERVERBOUND_PAYLOAD) {
                            throw new AssertionError("chunk exceeds the serverbound payload limit: " + chunk.length);
                        }
                        out.largestClientChunk = Math.max(out.largestClientChunk, chunk.length);
                        toServer.add(chunk);
                        out.clientToServerChunks++;
                    }

                    @Override
                    public void abort(String message) {
                        out.aborts.add(message);
                    }
                },
                clientWorker,
                RND,
                log);
        out.client = client;
        out.server = server;

        server.start();
        int guard = 0;
        while ((!toClient.isEmpty() || !toServer.isEmpty()) && guard++ < 10_000) {
            while (!toClient.isEmpty()) {
                client.onChunk(toClient.poll());
            }
            while (!toServer.isEmpty()) {
                server.onChunk(toServer.poll());
            }
        }
        return out;
    }
}
