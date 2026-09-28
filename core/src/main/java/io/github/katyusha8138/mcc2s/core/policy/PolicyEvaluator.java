// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.policy;

import io.github.katyusha8138.mcc2s.core.handshake.ProofContext;
import io.github.katyusha8138.mcc2s.core.model.Entry;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.model.Manifest;
import io.github.katyusha8138.mcc2s.core.model.Scope;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** クライアントのマニフェストをポリシーに照らして判定する(暗号処理は含まない純粋なロジック)。 */
public final class PolicyEvaluator {
    private PolicyEvaluator() {}

    /**
     * @param baseline サーバー自身の項目(サーバーに入っている Mod など)。種別ごとの許可の基準になる
     * @param trustedSelfHashes 許可する mcC2S 本体のハッシュ(署名済み公式ビルド一覧 + サーバー自身のビルド)
     * @param proofs 測定証明の検証コンテキスト。null なら測定証明を一切検証しない
     */
    public static Evaluation evaluate(
            PolicyConfig cfg,
            Manifest manifest,
            List<Entry> baseline,
            Set<String> trustedSelfHashes,
            ProofContext proofs,
            ReferenceResolver refs) {
        List<Violation> violations = new ArrayList<>();
        List<String> notices = new ArrayList<>();

        for (Scope s : cfg.scopes()) {
            if (!manifest.reportedScopes().contains(s)) {
                violations.add(new Violation(ViolationCode.SCOPE_MISSING, null, s.name(), "", "", "scope not reported"));
            }
        }

        int selfCount = 0;
        for (Entry e : manifest.entries()) {
            if (e.kind() != EntryKind.SELF) {
                continue;
            }
            selfCount++;
            if (!trustedSelfHashes.contains(e.sha256())) {
                violations.add(new Violation(
                        ViolationCode.SELF_UNOFFICIAL, e.kind(), e.id(), e.version(), e.sha256(), "not an official build"));
            }
            checkProof(cfg, e, proofs, refs, violations, notices);
        }
        if (selfCount == 0) {
            violations.add(new Violation(ViolationCode.SELF_MISSING, EntryKind.SELF, "mcc2s", "", "", "no self entry"));
        } else if (selfCount > 1) {
            violations.add(new Violation(
                    ViolationCode.DUPLICATE_SELF, EntryKind.SELF, "mcc2s", "", "", selfCount + " self entries"));
        }

        for (Entry e : manifest.entries()) {
            if (e.kind() == EntryKind.SELF) {
                continue;
            }
            if (!cfg.scopes().contains(e.kind().scope())) {
                notices.add("ignored " + e + " (scope " + e.kind().scope() + " not requested)");
                continue;
            }
            KindPolicy kp = cfg.kindPolicy(e.kind());
            List<Entry> base = baselineOf(baseline, e.kind());
            if (!kp.allows(e, base)) {
                Optional<Entry> same = kp.baselineWithSameId(e, base);
                if (kp.match() == MatchMode.HASH && kp.allowBaseline() && same.isPresent()) {
                    violations.add(new Violation(
                            ViolationCode.HASH_MISMATCH,
                            e.kind(),
                            e.id(),
                            e.version(),
                            e.sha256(),
                            "server has sha256=" + same.get().sha256()));
                } else {
                    violations.add(new Violation(
                            ViolationCode.NOT_ALLOWED, e.kind(), e.id(), e.version(), e.sha256(), "not in allow list"));
                }
                continue;
            }
            checkProof(cfg, e, proofs, refs, violations, notices);
        }
        return new Evaluation(violations, notices);
    }

    private static List<Entry> baselineOf(List<Entry> baseline, EntryKind kind) {
        List<Entry> out = new ArrayList<>();
        for (Entry b : baseline) {
            if (b.kind() == kind) {
                out.add(b);
            }
        }
        return out;
    }

    private static void checkProof(
            PolicyConfig cfg,
            Entry e,
            ProofContext proofs,
            ReferenceResolver refs,
            List<Violation> violations,
            List<String> notices) {
        if (proofs == null) {
            return;
        }
        boolean required = proofs.required(e.kind(), e.sha256());
        if (!required && e.proof() == null) {
            return;
        }
        Optional<InputStream> ref;
        try {
            ref = refs.open(e.kind(), e.sha256());
        } catch (IOException ex) {
            notices.add("could not read reference for " + e + ": " + ex.getMessage());
            return;
        }
        if (!ref.isPresent()) {
            if (required) {
                if (cfg.requireReference()) {
                    violations.add(new Violation(
                            ViolationCode.PROOF_UNVERIFIABLE,
                            e.kind(),
                            e.id(),
                            e.version(),
                            e.sha256(),
                            "no reference file to verify the proof"));
                } else {
                    notices.add("proof not verifiable (no reference file): " + e);
                }
            }
            return;
        }
        try (InputStream in = ref.get()) {
            if (e.proof() == null) {
                violations.add(new Violation(
                        ViolationCode.PROOF_MISSING, e.kind(), e.id(), e.version(), e.sha256(), "required proof absent"));
            } else if (!proofs.verify(e.kind(), e.sha256(), e.proof(), in)) {
                violations.add(new Violation(
                        ViolationCode.PROOF_INVALID, e.kind(), e.id(), e.version(), e.sha256(), "proof mismatch"));
            }
        } catch (IOException ex) {
            notices.add("could not read reference for " + e + ": " + ex.getMessage());
        }
    }
}
