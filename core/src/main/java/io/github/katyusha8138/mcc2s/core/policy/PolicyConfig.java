// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/** サーバー運営者が設定するポリシー全体(不変)。 */
public final class PolicyConfig {
    private final EnforcementMode mode;
    private final Set<Scope> scopes;
    private final int proofRatePercent;
    private final boolean requireReference;
    private final int handshakeTimeoutSeconds;
    private final boolean showDetailsToPlayer;
    private final boolean reverifyEnabled;
    private final boolean reverifyOnChange;
    private final int reverifyMinSeconds;
    private final int reverifyMaxSeconds;
    private final Map<EntryKind, KindPolicy> kinds;

    private PolicyConfig(Builder b) {
        if (b.proofRatePercent < 0 || b.proofRatePercent > 100) {
            throw new IllegalArgumentException("proof_rate_percent must be 0..100");
        }
        if (b.handshakeTimeoutSeconds < 5 || b.handshakeTimeoutSeconds > 300) {
            throw new IllegalArgumentException("handshake_timeout_seconds must be 5..300");
        }
        if (b.reverifyMinSeconds < 30 || b.reverifyMaxSeconds < b.reverifyMinSeconds) {
            throw new IllegalArgumentException("reverify requires 30 <= min_seconds <= max_seconds");
        }
        if (b.scopes.isEmpty()) {
            throw new IllegalArgumentException("scopes must not be empty");
        }
        this.mode = b.mode;
        this.scopes = Collections.unmodifiableSet(EnumSet.copyOf(b.scopes));
        this.proofRatePercent = b.proofRatePercent;
        this.requireReference = b.requireReference;
        this.handshakeTimeoutSeconds = b.handshakeTimeoutSeconds;
        this.showDetailsToPlayer = b.showDetailsToPlayer;
        this.reverifyEnabled = b.reverifyEnabled;
        this.reverifyOnChange = b.reverifyOnChange;
        this.reverifyMinSeconds = b.reverifyMinSeconds;
        this.reverifyMaxSeconds = b.reverifyMaxSeconds;
        EnumMap<EntryKind, KindPolicy> map = new EnumMap<>(EntryKind.class);
        for (EntryKind k : EntryKind.values()) {
            if (k != EntryKind.SELF) {
                map.put(k, b.kinds.getOrDefault(k, KindPolicy.defaults()));
            }
        }
        this.kinds = Collections.unmodifiableMap(map);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static PolicyConfig defaults() {
        return builder().build();
    }

    public EnforcementMode mode() {
        return mode;
    }

    public Set<Scope> scopes() {
        return scopes;
    }

    /** 測定証明を要求する項目の割合(%)。mcC2S 本体(SELF)は常に要求される。 */
    public int proofRatePercent() {
        return proofRatePercent;
    }

    /** true なら、要求された測定証明をサーバーが検証できない項目(参照ファイル無し)を違反にする。 */
    public boolean requireReference() {
        return requireReference;
    }

    public int handshakeTimeoutSeconds() {
        return handshakeTimeoutSeconds;
    }

    public boolean showDetailsToPlayer() {
        return showDetailsToPlayer;
    }

    public boolean reverifyEnabled() {
        return reverifyEnabled;
    }

    /** クライアントがリソースパックを切り替えたとき(再読み込み時)に、次の定期検証を待たず即座に再検証する。 */
    public boolean reverifyOnChange() {
        return reverifyOnChange;
    }

    public int reverifyMinSeconds() {
        return reverifyMinSeconds;
    }

    public int reverifyMaxSeconds() {
        return reverifyMaxSeconds;
    }

    public KindPolicy kindPolicy(EntryKind kind) {
        KindPolicy p = kinds.get(kind);
        if (p == null) {
            throw new IllegalArgumentException("no policy for " + kind);
        }
        return p;
    }

    public static final class Builder {
        private EnforcementMode mode = EnforcementMode.ENFORCE;
        private Set<Scope> scopes = EnumSet.allOf(Scope.class);
        private int proofRatePercent = 20;
        private boolean requireReference = false;
        private int handshakeTimeoutSeconds = 30;
        private boolean showDetailsToPlayer = false;
        private boolean reverifyEnabled = true;
        private boolean reverifyOnChange = true;
        private int reverifyMinSeconds = 300;
        private int reverifyMaxSeconds = 900;
        private final Map<EntryKind, KindPolicy> kinds = new EnumMap<>(EntryKind.class);

        public Builder mode(EnforcementMode v) {
            this.mode = v;
            return this;
        }

        public Builder scopes(Set<Scope> v) {
            this.scopes = v;
            return this;
        }

        public Builder proofRatePercent(int v) {
            this.proofRatePercent = v;
            return this;
        }

        public Builder requireReference(boolean v) {
            this.requireReference = v;
            return this;
        }

        public Builder handshakeTimeoutSeconds(int v) {
            this.handshakeTimeoutSeconds = v;
            return this;
        }

        public Builder showDetailsToPlayer(boolean v) {
            this.showDetailsToPlayer = v;
            return this;
        }

        public Builder reverify(boolean enabled, int minSeconds, int maxSeconds) {
            this.reverifyEnabled = enabled;
            this.reverifyMinSeconds = minSeconds;
            this.reverifyMaxSeconds = maxSeconds;
            return this;
        }

        public Builder reverifyOnChange(boolean v) {
            this.reverifyOnChange = v;
            return this;
        }

        public Builder kind(EntryKind kind, KindPolicy policy) {
            if (kind == EntryKind.SELF) {
                throw new IllegalArgumentException("SELF is governed by official builds, not by allow lists");
            }
            this.kinds.put(kind, policy);
            return this;
        }

        public PolicyConfig build() {
            return new PolicyConfig(this);
        }
    }
}
