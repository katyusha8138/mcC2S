# mcC2S

Minecraft サーバー運営者向けの**チート・不正対策 Mod**(Forge / NeoForge、サーバー+クライアント両導入)。

サーバー参加時にクライアントの Mod・リソースパック・シェーダーパック・JVM エージェントを照合し、
**サーバーに入っている Mod とホワイトリストで明示したもの以外**を持つクライアントの参加を拒否して
サーバーコンソールに報告します。シングルプレイや mcC2S 未導入のサーバーでは何もしません。
mcC2S 導入サーバーには、mcC2S 未導入(または信頼ファイルの無い)クライアントも参加できません。

> **状態: 開発中(M1 `core` + M2 NeoForge 1.21.1 アダプタ + M3 運用機能を実装済み)**。NeoForge 1.21.1 の専用サーバー+クライアントで
> 実機の動作確認済み(参加時の検証、プレイ中の定期再検証、リソース再読込時の即時再検証、`/mcc2s` コマンド、CLI、署名付きリリース CI)。
> リリース前に残っているのは、難読化のビルド統合と Forge 1.20.1 対応(M4)です。
> 計画は [docs/PLAN.md](docs/PLAN.md)、運用は [docs/OPERATIONS.md](docs/OPERATIONS.md)。

## 何を守れて、何を守れないか

クライアントは攻撃者の制御下にあるため、暗号だけで改造クライアントを完全に排除することはできません。
通信路・プロトコルは暗号学的に強く守り(なりすまし・リプレイ・改ざん・ダウングレード)、
クライアントの誠実さについては攻撃コストの引き上げと検知に重点を置きます。
詳細と残余リスクは [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)、通信仕様は [docs/PROTOCOL.md](docs/PROTOCOL.md) を参照してください。
プロキシ経由サーバーは現状未対応ですが、拡張余地を [docs/PROXY.md](docs/PROXY.md) にまとめています。

## 構成

| ディレクトリ | 内容 | 状態 |
|---|---|---|
| `core/` | 暗号ハンドシェイク・マニフェスト・ポリシー・設定・署名(Minecraft 非依存、Java 17 API) | 実装済み・テスト済み |
| `common/` | ファイル走査・検証の状態機械・設定ファイル生成・違反ログ(Minecraft 非依存、Java 17 API) | 実装済み・テスト済み |
| `neoforge/` | NeoForge 1.21.1 アダプタ(設定フェーズで検証) | 実装済み・実機 E2E 済み |
| `cli/` | `mcc2s-cli`(ハッシュ算出・鍵生成・信頼ファイル生成・リリース署名/検証) | 実装済み・テスト済み |
| `forge/` | Forge 1.20.1 アダプタ | 未着手(M4) |
| `tools/e2e/` | 実機エンドツーエンド試験(専用サーバー+実クライアント) | — |

## ライセンス

[GNU GPL v3.0 or later](LICENSE)。方針の詳細は [docs/LICENSING.md](docs/LICENSING.md)。

## ビルドとテスト

JDK 21 が必要です(`core` / `common` は Java 17 API に固定)。

```sh
./gradlew build                 # 全モジュールのビルドとユニットテスト
./gradlew :neoforge:jar         # 配布用 jar(core / common を同梱)
tools/e2e/e2e.sh                # 実機 E2E(専用サーバー+実クライアント。Xvfb / Mesa が必要)
```

## サーバー運営者向けの流れ

1. サーバーの `mods/` に mcC2S を入れて起動すると、`config/mcc2s/` に設定と鍵が自動生成されます。
2. `config/mcc2s/trust/server-*.mc2strust`(**信頼ファイル**)を Mod パックに同梱してプレイヤーに配布します。
   プレイヤーは `config/mcc2s/trust/` に置きます(秘密鍵は含まれません)。
3. 最初は `config/mcc2s/policy.toml` を `mode = "audit"` にして、ログ(`logs/mcc2s/violations.jsonl`)で
   誤検知を洗い出してから `enforce` にします。クライアント専用 Mod は、ログに出た SHA-256 を
   `[[mods.allow]]` に追加して許可します。

## 設定例(サーバー)

既定の設定は [`default-policy.toml`](core/src/main/resources/io/github/katyusha8138/mcc2s/default-policy.toml) にコメント付きで入っています。

```toml
mode = "audit"        # 導入時は audit で誤検知を洗い出し、問題なければ enforce に

[[mods.allow]]        # クライアント専用 Mod の許可(hash モードでは sha256 必須)
id = "sodium"
sha256 = ["<jar の SHA-256>"]
```

設定のタイプミス・曖昧な許可(hash モードで sha256 無し等)は、意図せず許可が広がらないよう起動時にエラーになります。
