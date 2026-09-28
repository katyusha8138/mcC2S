// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.handshake.ClientHandshake;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** 走査結果からマニフェストを組み立て、サーバーが要求した項目には測定証明(セッション束縛)を付ける。 */
public final class ManifestAssembler {
    /** クライアント環境の申告(サーバーのログ・診断用。ポリシー判定には使わない)。 */
    public record Env(String minecraftVersion, String loaderName, String loaderVersion, String mcC2SVersion) {}

    private ManifestAssembler() {}

    public static Manifest assemble(
            ClientHandshake handshake, List<EntrySeed> seeds, Set<Scope> reportedScopes, Env env) throws IOException {
        List<Entry> entries = new ArrayList<>(seeds.size());
        for (EntrySeed seed : seeds) {
            Entry e = seed.toEntry();
            if (seed.file() != null
                    && Files.isRegularFile(seed.file())
                    && handshake.proofs().required(e.kind(), e.sha256())) {
                try (InputStream in = Files.newInputStream(seed.file())) {
                    e = e.withProof(handshake.proofs().prove(e.kind(), e.sha256(), in));
                }
            }
            entries.add(e);
        }
        return new Manifest(
                Sanitize.text(env.minecraftVersion(), 64),
                Sanitize.text(env.loaderName(), 64),
                Sanitize.text(env.loaderVersion(), 64),
                Sanitize.text(env.mcC2SVersion(), 64),
                reportedScopes,
                entries);
    }
}
