// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.cli;

import java.io.PrintStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

/**
 * mcC2S の運営者・リリース担当向けコマンドラインツール。
 * <pre>
 * java -jar mcc2s-cli.jar &lt;コマンド&gt; [オプション]
 * </pre>
 * 終了コード: 0 = 成功 / 1 = 失敗(検証エラー・入出力エラー) / 2 = 使い方の誤り
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) {
        Charset cs = outputCharset();
        System.exit(run(args, new PrintStream(System.out, true, cs), new PrintStream(System.err, true, cs)));
    }

    /** コンソールが接続されていればその文字コード(Windows の日本語コンソール等)、なければ JVM の既定を使う。 */
    private static Charset outputCharset() {
        java.io.Console console = System.console();
        return console != null ? console.charset() : Charset.defaultCharset();
    }

    /** テストから呼べるように、標準入出力を差し替え可能にした入口。 */
    public static int run(String[] argv, PrintStream out, PrintStream err) {
        if (argv.length == 0 || argv[0].equals("help") || argv[0].equals("--help") || argv[0].equals("-h")) {
            out.print(USAGE);
            return argv.length == 0 ? 2 : 0;
        }
        String command = argv[0];
        List<String> rest = Arrays.asList(argv).subList(1, argv.length);
        try {
            switch (command) {
                case "hash":
                    return Commands.hash(rest, out, err);
                case "keygen":
                    return Commands.keygen(rest, out, err);
                case "pubkey":
                    return Commands.pubkey(rest, out, err);
                case "trustfile":
                    return Commands.trustfile(rest, out, err);
                case "rotate-secret":
                    return Commands.rotateSecret(rest, out, err);
                case "sign-release":
                    return Commands.signRelease(rest, out, err);
                case "verify-release":
                    return Commands.verifyRelease(rest, out, err);
                default:
                    err.println("不明なコマンド: " + command + "\n");
                    err.print(USAGE);
                    return 2;
            }
        } catch (Args.UsageException e) {
            err.println("使い方の誤り: " + e.getMessage());
            err.println("`help` で使い方を表示します。");
            return 2;
        } catch (Exception e) {
            err.println("エラー: " + e.getMessage());
            return 1;
        }
    }

    static final String USAGE = String.join(
            "\n",
            "mcc2s-cli — mcC2S 運営者・リリース担当向けツール",
            "",
            "サーバー運営者:",
            "  hash [--toml] [--kind K] [--id ID] [--version V] <パス>...",
            "      jar/フォルダの SHA-256 を表示する。--toml でホワイトリスト(policy.toml)に貼れる断片を出力する。",
            "      K = mod | library | resource-pack | shader-pack | agent | other-code(既定: mod)",
            "  trustfile --config <config/mcc2s> [--label 名前] [--out ファイル]",
            "      サーバーの鍵から、プレイヤーに配布する信頼ファイルを(再)生成する。",
            "  rotate-secret --config <config/mcc2s> [--label 名前]",
            "      pack_secret をローテーションする。旧鍵は猶予として残り、新しい信頼ファイルが生成される。",
            "",
            "リリース担当:",
            "  keygen --out <ファイル> [--force]",
            "      リリース署名鍵(Ed25519)を生成する。秘密鍵ファイルは絶対にコミット・共有しない。",
            "  pubkey --identity <ファイル>",
            "      秘密鍵ファイルから公開鍵(base64url)を表示する。",
            "  sign-release --key <鍵ファイル> --version V --loader L [--base 既存の一覧 ] [--out ファイル] <jar>...",
            "      公式ビルド一覧(official-builds.txt)に jar のハッシュを追記して署名する。",
            "      --base を指定すると、その一覧の署名を検証した上で、過去のビルドを引き継ぐ(追記専用)。",
            "  verify-release --pubkey <base64url またはファイル> <official-builds.txt>",
            "      公式ビルド一覧の署名を検証して、内容を表示する。",
            "");
}
