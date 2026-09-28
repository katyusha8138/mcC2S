// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.handshake.TrustFile;
import io.github.katyusha8138.mcc2s.core.handshake.TrustStore;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** クライアントの {@code config/mcc2s/trust/} にある信頼ファイル({@code *.mc2strust})の読み込み。 */
public final class TrustFiles {
    private TrustFiles() {}

    /** 壊れたファイルはログに出して読み飛ばす(他のサーバー用の正常なファイルまで巻き込まない)。 */
    public static TrustStore load(Path trustDir, Log log) {
        List<TrustFile> files = new ArrayList<>();
        if (Files.isDirectory(trustDir)) {
            List<Path> paths;
            try (Stream<Path> s = Files.list(trustDir)) {
                paths = s.filter(Files::isRegularFile)
                        .filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".mc2strust"))
                        .sorted()
                        .collect(Collectors.toList());
            } catch (IOException e) {
                log.error("[mcC2S] could not list " + trustDir, e);
                paths = List.of();
            }
            for (Path p : paths) {
                try {
                    files.add(TrustFile.parse(Files.readString(p, StandardCharsets.UTF_8)));
                } catch (IOException | java.security.GeneralSecurityException e) {
                    log.warn("[mcC2S] ignoring invalid trust file " + p.getFileName() + ": " + e.getMessage());
                }
            }
        }
        return new TrustStore(files);
    }
}
