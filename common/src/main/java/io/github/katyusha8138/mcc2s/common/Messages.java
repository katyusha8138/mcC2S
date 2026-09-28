// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.common;

import io.github.katyusha8138.mcc2s.core.policy.Violation;
import java.util.List;

/**
 * プレイヤーに表示する文言。mcC2S 未導入のクライアントにも読めるよう、翻訳キーではなく日英併記の文字列にする。
 * 詳細(Mod 名など)は既定では含めず、参照コードだけを出す(設定 show_details_to_player で切替)。
 */
public final class Messages {
    private static final int MAX_DETAIL_LINES = 6;

    private Messages() {}

    public static String denied(String refCode, List<Violation> detailsOrNull) {
        StringBuilder sb = new StringBuilder();
        sb.append("[mcC2S] 許可されていない Mod・リソースパック等が検出されたため参加できません。\n");
        sb.append("[mcC2S] Unauthorized mods or resource packs were detected.\n");
        if (detailsOrNull != null) {
            int shown = 0;
            for (Violation v : detailsOrNull) {
                if (shown++ >= MAX_DETAIL_LINES) {
                    sb.append("  ... (+").append(detailsOrNull.size() - MAX_DETAIL_LINES).append(")\n");
                    break;
                }
                sb.append("  - ").append(v.kind() == null ? "" : v.kind() + " ").append(v.id()).append('\n');
            }
        }
        sb.append("参照コード / Ref: ").append(refCode);
        return sb.toString();
    }

    public static String required() {
        return "[mcC2S] このサーバーには mcC2S が必要です。クライアントに mcC2S を導入してください。\n"
                + "[mcC2S] This server requires the mcC2S mod on the client.";
    }

    public static String timeout() {
        return "[mcC2S] クライアント検証がタイムアウトしました。mcC2S と、このサーバーの信頼ファイルが導入されているか確認してください。\n"
                + "[mcC2S] Client verification timed out. Make sure mcC2S and this server's trust file are installed.";
    }

    public static String failed(String refCode) {
        return "[mcC2S] クライアント検証に失敗しました。\n"
                + "[mcC2S] Client verification failed.\n"
                + "参照コード / Ref: " + refCode;
    }

    public static String busy() {
        return "[mcC2S] サーバーが混み合っています。しばらくしてから再接続してください。\n"
                + "[mcC2S] The server is busy. Please try again shortly.";
    }

    // ---- クライアント側 ----

    public static String noTrustFile() {
        return "[mcC2S] このサーバーの信頼ファイル(.mc2strust)がありません。\n"
                + "サーバー運営者から入手し、config/mcc2s/trust/ フォルダに置いてください。\n"
                + "[mcC2S] Missing trust file for this server. Get it from the server owner and put it in config/mcc2s/trust/.";
    }

    public static String badServerSignature() {
        return "[mcC2S] サーバーの署名を検証できませんでした(信頼ファイルが古い、または偽のサーバーの可能性があります)。\n"
                + "[mcC2S] Could not verify the server's signature (outdated trust file, or an impostor server).";
    }

    public static String clientFailed(String detail) {
        return "[mcC2S] 検証を完了できませんでした: " + detail + "\n[mcC2S] Verification could not be completed.";
    }
}
