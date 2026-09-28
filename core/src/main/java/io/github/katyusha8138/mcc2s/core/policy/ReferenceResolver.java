// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

/**
 * サーバーが持っている「参照ファイル」の解決。測定証明({@link io.github.katyusha8138.mcc2s.core.handshake.ProofContext})を
 * 検証するには、サーバーが同じバイト列を持っている必要がある。
 * 通常は、サーバー自身の Mod jar・mcC2S 本体・運営者が {@code reference/} に置いた jar が対象。
 * 戻り値のストリームの SHA-256 が {@code sha256Hex} と一致することは実装側が保証する。
 */
@FunctionalInterface
public interface ReferenceResolver {
    Optional<InputStream> open(EntryKind kind, String sha256Hex) throws IOException;

    static ReferenceResolver none() {
        return (kind, sha) -> Optional.empty();
    }
}
