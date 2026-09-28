// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;

/** 違反報告の出力先。 */
@FunctionalInterface
public interface ViolationSink {
    void report(ViolationReport report);
}
