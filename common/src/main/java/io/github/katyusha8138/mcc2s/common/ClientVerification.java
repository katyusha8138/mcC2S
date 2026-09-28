// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.handshake.ClientHandshake;
import io.github.katyusha8138.mcc2s.core.handshake.Fragmenter;
import io.github.katyusha8138.mcc2s.core.handshake.HandshakeException;
import io.github.katyusha8138.mcc2s.core.handshake.Reassembler;
import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.handshake.TrustStore;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;

/**
 * 1 接続分のクライアント側検証。サーバーのチャレンジを受け、自分の構成を集めて暗号化して返す。
 * 重い処理(ファイルのハッシュ計算)は {@code worker} で行い、ゲームのスレッドを塞がない
 * (塞ぐとキープアライブが切れて接続が落ちる)。
 */
public final class ClientVerification {
    public interface Transport {
        /** チャンク 1 つをサーバーへ送る(どのスレッドから呼んでもよい)。 */
        void send(byte[] chunk);

        /** クライアント側から接続を中止する。{@code message} はプレイヤーに表示される。 */
        void abort(String message);
    }

    /** ローダー固有の情報(リソースパック・シェーダーパック等)を含む項目の収集。 */
    public interface Collector {
        Collected collect(Set<Scope> requested) throws Exception;
    }

    public record Collected(Set<Scope> reportedScopes, List<EntrySeed> seeds) {}

    private static final int MAX_CHALLENGE_BYTES = 4096;
    private static final int MAX_VERDICT_BYTES = 8192;
    private static final int MAX_CHUNKS = 16;

    private enum State {
        AWAIT_CHALLENGE,
        BUSY,
        AWAIT_VERDICT,
        DONE
    }

    private final Supplier<TrustStore> trust;
    private final byte[] context;
    private final Collector collector;
    private final ManifestAssembler.Env env;
    private final Transport transport;
    private final Executor worker;
    private final SecureRandom random;
    private final Log log;

    private final Reassembler challengeAssembler = new Reassembler(Fragmenter.TYPE_CHALLENGE, MAX_CHALLENGE_BYTES, MAX_CHUNKS);
    private final Reassembler verdictAssembler = new Reassembler(Fragmenter.TYPE_VERDICT, MAX_VERDICT_BYTES, MAX_CHUNKS);
    private State state = State.AWAIT_CHALLENGE;
    private volatile ClientHandshake handshake;
    private ServerVerdict verdict;

    public ClientVerification(
            Supplier<TrustStore> trust,
            byte[] context,
            Collector collector,
            ManifestAssembler.Env env,
            Transport transport,
            Executor worker,
            SecureRandom random,
            Log log) {
        this.trust = trust;
        this.context = context;
        this.collector = collector;
        this.env = env;
        this.transport = transport;
        this.worker = worker;
        this.random = random;
        this.log = log;
    }

    /** サーバーからのチャンク(チャレンジ、または判定)。 */
    public void onChunk(byte[] chunkBytes) {
        byte[] challenge = null;
        byte[] verdictBytes = null;
        synchronized (this) {
            try {
                Fragmenter.Chunk chunk = Fragmenter.Chunk.decode(chunkBytes);
                if (state == State.AWAIT_CHALLENGE) {
                    Optional<byte[]> done = challengeAssembler.accept(chunk);
                    if (done.isEmpty()) {
                        return;
                    }
                    challenge = done.get();
                    state = State.BUSY;
                } else if (state == State.AWAIT_VERDICT) {
                    Optional<byte[]> done = verdictAssembler.accept(chunk);
                    if (done.isEmpty()) {
                        return;
                    }
                    verdictBytes = done.get();
                    state = State.DONE;
                } else {
                    return; // 処理中・完了後の余分な入力は無視
                }
            } catch (WireException e) {
                state = State.DONE;
                transport.abort(Messages.clientFailed("malformed data from server"));
                return;
            }
        }
        if (challenge != null) {
            byte[] c = challenge;
            try {
                worker.execute(() -> respond(c));
            } catch (RejectedExecutionException e) {
                fail(Messages.clientFailed("worker unavailable"));
            }
        } else if (verdictBytes != null) {
            readVerdict(verdictBytes);
        }
    }

    private void respond(byte[] challenge) {
        try {
            try {
                handshake = ClientHandshake.accept(trust.get(), challenge, context, random);
            } catch (HandshakeException e) {
                switch (e.reason()) {
                    case UNTRUSTED_SERVER:
                        fail(Messages.noTrustFile());
                        break;
                    case BAD_SIGNATURE:
                        fail(Messages.badServerSignature());
                        break;
                    default:
                        fail(Messages.clientFailed(e.reason().toString()));
                }
                return;
            }

            Set<Scope> requested = handshake.requestedScopes();
            Collected collected = collector.collect(requested);
            Set<Scope> reported = EnumSet.noneOf(Scope.class);
            reported.addAll(collected.reportedScopes());
            Manifest manifest = ManifestAssembler.assemble(handshake, collected.seeds(), reported, env);
            log.info("[mcC2S] sending " + manifest.entries().size() + " entries to the server for verification "
                    + "(mod/resource pack IDs, versions and SHA-256 hashes only)");

            byte[] attestation = handshake.attest(manifest);
            synchronized (this) {
                state = State.AWAIT_VERDICT;
            }
            for (Fragmenter.Chunk c : Fragmenter.split(Fragmenter.TYPE_ATTESTATION, attestation, ServerContext.CHUNK_BYTES)) {
                transport.send(c.encode());
            }
        } catch (Exception e) {
            log.error("[mcC2S] client verification failed", e);
            fail(Messages.clientFailed(e.getClass().getSimpleName()));
        }
    }

    private void readVerdict(byte[] verdictBytes) {
        try {
            ServerVerdict v = handshake.readVerdict(verdictBytes);
            synchronized (this) {
                verdict = v;
            }
            log.info("[mcC2S] server verdict: " + v.status());
            if (v.status() == ServerVerdict.Status.DENIED) {
                transport.abort(v.message());
            }
        } catch (HandshakeException e) {
            fail(Messages.clientFailed("invalid verdict"));
        }
    }

    private void fail(String message) {
        synchronized (this) {
            state = State.DONE;
        }
        transport.abort(message);
    }

    public synchronized Optional<ServerVerdict> verdict() {
        return Optional.ofNullable(verdict);
    }
}
