// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.handshake.Ed25519Identity;
import io.github.katyusha8138.mcc2s.core.handshake.PackSecrets;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.policy.PolicyConfig;
import io.github.katyusha8138.mcc2s.core.policy.ReferenceResolver;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;

/** サーバー側の検証に必要な共有状態(1 サーバーに 1 つ)。ローダーアダプタが起動時に組み立てる。 */
public final class ServerContext {
    /** Minecraft のサーバー行きカスタムペイロード上限(約 32KB)に余裕を持たせたチャンク本体サイズ。 */
    public static final int CHUNK_BYTES = 28_000;

    private final Ed25519Identity identity;
    private final PackSecrets secrets;
    private final PolicyConfig policy;
    private final List<Entry> baseline;
    private final Set<String> trustedSelfHashes;
    private final ReferenceResolver references;
    private final ViolationSink sink;
    private final Log log;
    private final SecureRandom random;
    private final Executor worker;
    private final Clock clock;
    private final ServerStats stats;

    private ServerContext(Builder b) {
        this.identity = Objects.requireNonNull(b.identity, "identity");
        this.secrets = Objects.requireNonNull(b.secrets, "secrets");
        this.policy = Objects.requireNonNull(b.policy, "policy");
        this.baseline = List.copyOf(b.baseline);
        this.trustedSelfHashes = Set.copyOf(b.trustedSelfHashes);
        this.references = Objects.requireNonNull(b.references, "references");
        this.sink = Objects.requireNonNull(b.sink, "sink");
        this.log = Objects.requireNonNull(b.log, "log");
        this.random = b.random == null ? new SecureRandom() : b.random;
        this.worker = Objects.requireNonNull(b.worker, "worker");
        this.clock = b.clock == null ? Clock.systemUTC() : b.clock;
        this.stats = b.stats == null ? new ServerStats() : b.stats;
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

    /** サーバー自身の Mod/ライブラリ。許可の基準になる。 */
    public List<Entry> baseline() {
        return baseline;
    }

    /** 許可する mcC2S 本体のハッシュ(サーバー自身のビルド + 署名済み公式ビルド一覧)。 */
    public Set<String> trustedSelfHashes() {
        return trustedSelfHashes;
    }

    public ReferenceResolver references() {
        return references;
    }

    public ViolationSink sink() {
        return sink;
    }

    public Log log() {
        return log;
    }

    public SecureRandom random() {
        return random;
    }

    /** 重い処理(参照ファイルのハッシュ検証など)を行うスレッド。ネットワーク/メインスレッドを塞がない。 */
    public Executor worker() {
        return worker;
    }

    public Clock clock() {
        return clock;
    }

    public ServerStats stats() {
        return stats;
    }

    /** 設定の再読込などで一部だけ差し替えた新しいコンテキストを作る(統計・ワーカー等は共有される)。 */
    public Builder toBuilder() {
        return new Builder()
                .identity(identity)
                .secrets(secrets)
                .policy(policy)
                .baseline(baseline)
                .trustedSelfHashes(trustedSelfHashes)
                .references(references)
                .sink(sink)
                .log(log)
                .random(random)
                .worker(worker)
                .clock(clock)
                .stats(stats);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Ed25519Identity identity;
        private PackSecrets secrets;
        private PolicyConfig policy;
        private List<Entry> baseline = List.of();
        private Set<String> trustedSelfHashes = Set.of();
        private ReferenceResolver references = ReferenceResolver.none();
        private ViolationSink sink;
        private Log log;
        private SecureRandom random;
        private Executor worker;
        private Clock clock;
        private ServerStats stats;

        public Builder stats(ServerStats v) {
            this.stats = v;
            return this;
        }

        public Builder identity(Ed25519Identity v) {
            this.identity = v;
            return this;
        }

        public Builder secrets(PackSecrets v) {
            this.secrets = v;
            return this;
        }

        public Builder policy(PolicyConfig v) {
            this.policy = v;
            return this;
        }

        public Builder baseline(List<Entry> v) {
            this.baseline = v;
            return this;
        }

        public Builder trustedSelfHashes(Set<String> v) {
            this.trustedSelfHashes = v;
            return this;
        }

        public Builder references(ReferenceResolver v) {
            this.references = v;
            return this;
        }

        public Builder sink(ViolationSink v) {
            this.sink = v;
            return this;
        }

        public Builder log(Log v) {
            this.log = v;
            return this;
        }

        public Builder random(SecureRandom v) {
            this.random = v;
            return this;
        }

        public Builder worker(Executor v) {
            this.worker = v;
            return this;
        }

        public Builder clock(Clock v) {
            this.clock = v;
            return this;
        }

        public ServerContext build() {
            return new ServerContext(this);
        }
    }
}
