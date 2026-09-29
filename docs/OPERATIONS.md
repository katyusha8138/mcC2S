# サーバー運営ガイド

## 導入

1. サーバーの `mods/` に mcC2S の jar を入れて起動します。`config/mcc2s/` に次のものが自動生成されます。

   | ファイル | 内容 |
   |---|---|
   | `policy.toml` | ポリシー(あなたが編集する) |
   | `server_identity.txt` | サーバー識別の**秘密鍵**(絶対に配布しない・コミットしない) |
   | `pack_secrets.txt` | pack_secret(**秘密**。配布しない) |
   | `trust/server-*.mc2strust` | **プレイヤーに配布する信頼ファイル**(公開鍵 + pack_secret) |
   | `reference/` | 測定証明の検証に使う参照 jar を置く場所(任意) |
   | `official-builds.txt` | 署名済みの公式ビルド一覧(任意) |

2. `trust/*.mc2strust` を Mod パックに同梱してプレイヤーに配布します。プレイヤーは
   `config/mcc2s/trust/` に置きます(mcC2S 本体も必要です)。信頼ファイルは
   **サーバーの参加者に配るものです。公開掲示板には載せないでください。**
3. まず `policy.toml` の `mode = "audit"` で運用し、ログで誤検知を確認してから `enforce` にします。

## 対応するローダーとバージョン

| ローダー | Minecraft | jar | Java | 動作確認 |
|---|---|---|---|---|
| NeoForge | 1.21.1 | `mcc2s-neoforge-1.21.1-<版>.jar` | 21 | 21.1.252 |
| Forge | 1.20.1 | `mcc2s-forge-1.20.1-<版>.jar` | 17 | 47.4.10(`[47,)` を許容) |

サーバーとクライアントには**同じローダー用の jar** を入れます(Minecraft のバージョンも違うため、そもそも混在できません)。
信頼ファイルはローダーに依存しません。

**Forge 1.20.1 の注意**: Forge 1.20.1 には NeoForge の「設定フェーズ」が無いため、検証はログイン交渉の中で行います
(検証が終わるまでワールドには入れません)。バニラのログインは全体で 30 秒(認証・レジストリ同期を含む)で切られるため、
参加時の検証の時間上限は `handshake_timeout_seconds` と **20 秒のうち短い方**になります。
`handshake_timeout_seconds` を 20 秒より長くしても、Forge の参加時の検証は 20 秒で打ち切られます
(プレイ中の再検証には 20 秒の上限はありません)。

## クライアント専用 Mod を許可する

Sodium などクライアントだけに入れる Mod は、ホワイトリストに載せます(hash モードでは SHA-256 が必要)。

- **audit 中のログから**: プレイヤーが違反として記録されたら
  `/mcc2s whitelist add <プレイヤー名>` でそのプレイヤーの直近の違反(許可できるもの)をまとめて追加できます。
  追加内容は応答にすべて表示され、`policy.toml` の末尾に追記されて即座に反映されます。
- **ハッシュを直接**: `/mcc2s whitelist addhash mod <sha256> [id]`
- **CLI で下書き**: `java -jar mcc2s-cli.jar hash --toml sodium.jar` で `[[mods.allow]]` の断片を作れます。
  jar の `mods.toml` から ID とバージョンを読み取ります。

> `whitelist add` は、そのプレイヤーが報告した内容をそのまま許可します。**追加前に、表示される Mod 名とハッシュが
> 想定どおりか確認してください**(audit モードで違反として出たものを、後から `add` するのが安全です)。

## コマンド(OP レベル 3 以上、またはサーバーコンソール)

| コマンド | 内容 |
|---|---|
| `/mcc2s status` | モード・ポリシー・集計(検証成功/拒否/再検証など) |
| `/mcc2s reload` | `policy.toml` と `official-builds.txt` を再読込(壊れていたら従来の設定を維持) |
| `/mcc2s whitelist add <player>` | そのプレイヤーの直近の違反を許可リストに追加 |
| `/mcc2s whitelist addhash <kind> <sha256> [id]` | ハッシュを直接許可(kind: mod, library, resource-pack, shader-pack, agent, other-code) |

## プレイ中の再検証

参加後も、ランダムな間隔(既定 5〜15 分)で再検証します。ログイン後に導入されたものや、書き換えられたものを検知でき、
違反・無応答のプレイヤーは切断されます。リソースパックを切り替えた(リソースが再読み込みされた)クライアントは、
次の定期検証を待たずに再検証されます(`[reverify] on_change`)。無効にするには `[reverify] enabled = false`。

## pack_secret のローテーション

信頼ファイルが流出した疑いがある、または定期的に更新したい場合:

```sh
java -jar mcc2s-cli.jar rotate-secret --config config/mcc2s
```

新しい信頼ファイルが生成され、旧鍵は猶予として残ります(旧信頼ファイルのプレイヤーも参加できる)。
全員が新しい信頼ファイルに更新したら、`pack_secrets.txt` の `previous` 行を削除して `/mcc2s reload` してください。

## 公式ビルドの一覧(`official-builds.txt`)

リリースには署名済みの `official-builds.txt` が付きます。`config/mcc2s/` に置くと、
サーバーの mcC2S と**バージョンが違っても**、公式ビルドであれば許可されます。置かない場合は、
サーバーと同一ビルドの mcC2S だけが許可されます(最も厳格)。

## ログ

- コンソール: `[mcC2S] DENIED <名前> ... ref=MC2S-XXXXXXXXXXXXXXXX` と違反項目
- `logs/mcc2s/violations.jsonl`: 1 行 1 レコードの JSON(参照コード・プレイヤー・違反の種類・ハッシュ)
- プレイヤーには参照コードだけが表示され、詳細は出ません(`show_details_to_player = true` で表示可)

## 既知の限界

`docs/THREAT_MODEL.md` を必ず読んでください。クライアントは改造され得るため、mcC2S は
「汎用チートの排除」と「攻撃コストの引き上げ」を目的とし、完全な防止は保証しません。
