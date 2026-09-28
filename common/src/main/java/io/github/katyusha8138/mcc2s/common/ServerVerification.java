// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.crypto.Digests;
import io.github.katyusha8138.mcc2s.core.handshake.Fragmenter;
import io.github.katyusha8138.mcc2s.core.handshake.HandshakeException;
import io.github.katyusha8138.mcc2s.core.handshake.Reassembler;
import io.github.katyusha8138.mcc2s.core.handshake.ServerHandshake;
import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.policy.Evaluation;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.PolicyEvaluator;
import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;

/**
 * 1 接続分のサーバー側検証。輸送路(Minecraft のパケット)には依存せず、{@link Transport} 越しに
 * チャンクを送り、結果を「許可(allow)」か「切断(kick)」で通知する。
 * <p>
 * 失敗はすべて閉じる方向(切断)に倒す。例外・不正入力・タイムアウトで通してしまうことはない。
 */
public final class ServerVerification {
    /** ローダーアダプタが実装する。{@code kick}/{@code allow} はアダプタがサーバースレッドへ引き渡すこと。 */
    public interface Transport {
        /** チャンク 1 つをクライアントへ送る(どのスレッドから呼ばれてもよい)。 */
        void send(byte[] chunk);

        /** 接続を切る。{@code message} はプレイヤーに表示される。 */
        void kick(String message);

        /** 検証成功。次の設定タスクに進める。 */
        void allow();
    }

    public record Player(String name, UUID id, String address) {}

    private enum State {
        AWAIT_ATTESTATION,
        EVALUATING,
        DONE
    }

    private static final int MAX_ATTESTATION_BYTES = 3 * 1024 * 1024;
    private static final int MAX_CHUNKS = 256;

    private final ServerContext ctx;
    private final Player player;
    private final Transport transport;
    private final PolicyConfig policy;
    private ServerHandshake handshake;
    private Reassembler reassembler;
    private State state = State.AWAIT_ATTESTATION;

    public ServerVerification(ServerContext ctx, Player player, Transport transport) {
        this.ctx = ctx;
        this.player = player;
        this.transport = transport;
        this.policy = ctx.policy(); // 接続中にポリシーが変わっても、この接続には開始時点のものを一貫して適用する
    }

    public PolicyConfig policy() {
        return policy;
    }

    /** チャレンジを作って送る。 */
    public synchronized void start() {
        try {
            handshake = ServerHandshake.start(
                    ctx.identity(),
                    ctx.secrets(),
                    policy.scopes(),
                    policy.proofRatePercent(),
                    Bindings.player(player.name()),
                    ctx.random());
            reassembler = new Reassembler(Fragmenter.TYPE_ATTESTATION, MAX_ATTESTATION_BYTES, MAX_CHUNKS);
            for (Fragmenter.Chunk c : Fragmenter.split(Fragmenter.TYPE_CHALLENGE, handshake.challenge(), ServerContext.CHUNK_BYTES)) {
                transport.send(c.encode());
            }
        } catch (Exception e) {
            failClosed("could not start verification", e);
        }
    }

    /** クライアントからのチャンク。不正なら即切断(失敗しても以降の入力は受け付けない)。 */
    public void onChunk(byte[] chunkBytes) {
        byte[] complete;
        synchronized (this) {
            if (state != State.AWAIT_ATTESTATION) {
                return; // 評価中・完了後の余分な入力は無視(切断済みか、評価結果待ち)
            }
            try {
                Optional<byte[]> done = reassembler.accept(Fragmenter.Chunk.decode(chunkBytes));
                if (done.isEmpty()) {
                    return;
                }
                complete = done.get();
            } catch (WireException e) {
                failClosed("malformed chunk: " + e.getMessage(), null);
                return;
            }
            state = State.EVALUATING;
        }
        try {
            ctx.worker().execute(() -> evaluate(complete));
        } catch (RejectedExecutionException e) {
            synchronized (this) {
                state = State.DONE;
            }
            ctx.log().warn("[mcC2S] verification queue is full; rejecting " + player.name());
            transport.kick(Messages.busy());
        }
    }

    /** アダプタがタイムアウト時に呼ぶ。応答待ちのままなら切断する(評価中は結果を待つ)。 */
    public void onTimeout() {
        synchronized (this) {
            if (state != State.AWAIT_ATTESTATION) {
                return;
            }
            state = State.DONE;
        }
        ctx.log().warn("[mcC2S] " + player.name() + " (" + player.id() + ") did not answer within "
                + policy.handshakeTimeoutSeconds() + "s (client probably lacks mcC2S or the trust file); kicking");
        transport.kick(Messages.timeout());
    }

    /** クライアントに mcC2S のチャンネルが無い(未導入・別 Mod ローダー等)。 */
    public void onClientLacksMod() {
        synchronized (this) {
            if (state == State.DONE) {
                return;
            }
            state = State.DONE;
        }
        ctx.log().warn("[mcC2S] " + player.name() + " (" + player.id() + ") from " + player.address()
                + " does not have mcC2S installed; kicking");
        transport.kick(Messages.required());
    }

    private void evaluate(byte[] attestation) {
        try {
            var opened = handshake.open(attestation);
            Manifest manifest = opened.manifest();
            Evaluation eval = PolicyEvaluator.evaluate(
                    policy, manifest, ctx.baseline(), ctx.trustedSelfHashes(), opened.proofs(), ctx.references());

            byte[] refId = new byte[ServerVerdict.REF_ID_LEN];
            ctx.random().nextBytes(refId);
            boolean permit = eval.permits(policy.mode());

            if (!eval.clean()) {
                ctx.sink().report(new ViolationReport(
                        Instant.now(ctx.clock()),
                        player.name(),
                        player.id(),
                        player.address(),
                        refId,
                        permit ? ServerVerdict.Status.AUDIT_ALLOWED : ServerVerdict.Status.DENIED,
                        eval.violations()));
            }
            if (!eval.notices().isEmpty()) {
                ctx.log().info("[mcC2S] " + player.name() + ": " + eval.notices().size() + " notice(s), e.g. "
                        + eval.notices().get(0));
            }

            if (!permit) {
                finish(State.DONE);
                String ref = "MC2S-" + Digests.hex(refId).toUpperCase(Locale.ROOT);
                transport.kick(Messages.denied(ref, policy.showDetailsToPlayer() ? eval.violations() : null));
                return;
            }

            ServerVerdict.Status status = eval.clean() ? ServerVerdict.Status.ALLOWED : ServerVerdict.Status.AUDIT_ALLOWED;
            ServerVerdict verdict = new ServerVerdict(status, 0, refId, "", 0);
            byte[] sealed = opened.sealVerdict(verdict);
            finish(State.DONE);
            for (Fragmenter.Chunk c : Fragmenter.split(Fragmenter.TYPE_VERDICT, sealed, ServerContext.CHUNK_BYTES)) {
                transport.send(c.encode());
            }
            ctx.log().info("[mcC2S] " + player.name() + " verified (" + manifest.entries().size() + " entries"
                    + (status == ServerVerdict.Status.AUDIT_ALLOWED ? ", audit mode: violations logged" : "") + ")");
            transport.allow();
        } catch (HandshakeException e) {
            finish(State.DONE);
            byte[] refId = new byte[ServerVerdict.REF_ID_LEN];
            ctx.random().nextBytes(refId);
            String ref = "MC2S-" + Digests.hex(refId).toUpperCase(Locale.ROOT);
            ctx.log().warn("[mcC2S] handshake failed for " + player.name() + " (" + player.id() + ") from "
                    + player.address() + ": " + e.reason() + " ref=" + ref);
            transport.kick(Messages.failed(ref));
        } catch (Throwable t) {
            failClosed("unexpected error while verifying " + player.name(), t);
        }
    }

    private synchronized void finish(State s) {
        state = s;
    }

    private void failClosed(String what, Throwable cause) {
        finish(State.DONE);
        ctx.log().error("[mcC2S] " + what, cause);
        byte[] refId = new byte[ServerVerdict.REF_ID_LEN];
        ctx.random().nextBytes(refId);
        transport.kick(Messages.failed("MC2S-" + Digests.hex(refId).toUpperCase(Locale.ROOT)));
    }

    /** テスト用。 */
    synchronized boolean isDone() {
        return state == State.DONE;
    }
}
