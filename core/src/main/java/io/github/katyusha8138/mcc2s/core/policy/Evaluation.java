// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** ポリシー評価の結果。 */
public final class Evaluation {
    private final List<Violation> violations;
    private final List<String> notices;

    public Evaluation(List<Violation> violations, List<String> notices) {
        this.violations = Collections.unmodifiableList(new ArrayList<>(violations));
        this.notices = Collections.unmodifiableList(new ArrayList<>(notices));
    }

    public List<Violation> violations() {
        return violations;
    }

    /** 違反ではないが管理者が知っておくべき事項(測定証明を検証できなかった件数など)。 */
    public List<String> notices() {
        return notices;
    }

    public boolean clean() {
        return violations.isEmpty();
    }

    /** 接続を通してよいか。audit モードでは違反があっても通す。 */
    public boolean permits(EnforcementMode mode) {
        return clean() || mode == EnforcementMode.AUDIT;
    }
}
