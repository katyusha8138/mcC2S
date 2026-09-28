// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

/** ローダー側のロガー(Log4j/SLF4J 等)へつなぐための最小インターフェース。 */
public interface Log {
    void info(String message);

    void warn(String message);

    void error(String message, Throwable cause);

    /** テスト・CLI 用の標準出力ロガー。 */
    static Log stdout() {
        return new Log() {
            @Override
            public void info(String message) {
                System.out.println("[INFO] " + message);
            }

            @Override
            public void warn(String message) {
                System.out.println("[WARN] " + message);
            }

            @Override
            public void error(String message, Throwable cause) {
                System.out.println("[ERROR] " + message + (cause == null ? "" : " : " + cause));
            }
        };
    }
}
