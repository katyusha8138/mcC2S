// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.policy.ViolationReport;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** 違反をサーバーコンソールに出し、{@code violations.jsonl}(1 行 1 レコード)にも追記する。 */
public final class ViolationLog implements ViolationSink {
    private final Path file;
    private final Log log;

    public ViolationLog(Path file, Log log) {
        this.file = file;
        this.log = log;
    }

    @Override
    public synchronized void report(ViolationReport report) {
        for (String line : report.consoleLines()) {
            log.warn(line);
        }
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(
                    file,
                    (report.toJsonLine() + "\n").getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.error("could not write " + file, e);
        }
    }
}
