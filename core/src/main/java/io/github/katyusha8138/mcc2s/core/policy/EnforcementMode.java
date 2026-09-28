// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

public enum EnforcementMode {
    /** 違反者の接続を拒否する。 */
    ENFORCE,
    /** 違反を記録するだけで通す(導入初期の誤検知洗い出し用)。 */
    AUDIT
}
