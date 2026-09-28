# mcC2S

Minecraft サーバー運営者向けの**チート・不正対策 Mod**(Forge / NeoForge、サーバー+クライアント両導入)。

サーバー参加時にクライアントの Mod・リソースパック・シェーダーパック・JVM エージェントを照合し、
**サーバーに入っている Mod とホワイトリストで明示したもの以外**を持つクライアントの参加を拒否して
サーバーコンソールに報告します。シングルプレイや mcC2S 未導入のサーバーでは何もしません。
mcC2S 導入サーバーには、mcC2S 未導入(または信頼ファイルの無い)クライアントも参加できません。

> **状態: 開発中(M1: ローダー非依存の `core` を実装済み)**。まだ Minecraft に導入できる Mod ではありません。
> 計画は [docs/PLAN.md](docs/PLAN.md)。

## 何を守れて、何を守れないか

クライアントは攻撃者の制御下にあるため、暗号だけで改造クライアントを完全に排除することはできません。
通信路・プロトコルは暗号学的に強く守り(なりすまし・リプレイ・改ざん・ダウングレード)、
クライアントの誠実さについては攻撃コストの引き上げと検知に重点を置きます。
詳細と残余リスクは [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)、通信仕様は [docs/PROTOCOL.md](docs/PROTOCOL.md) を参照してください。

## 構成

| ディレクトリ | 内容 | 状態 |
|---|---|---|
| `core/` | 暗号ハンドシェイク・マニフェスト・ポリシー・設定・署名(Minecraft 非依存、Java 17 API) | 実装済み・テスト済み |
| `neoforge/` | NeoForge 1.21.1 アダプタ | 未着手(M2) |
| `forge/` | Forge 1.20.1 アダプタ | 未着手(M4) |

## ビルドとテスト

JDK 17 以上が必要です(`core` は Java 17 API に固定)。

```sh
./gradlew :core:test
```

## 設定例(サーバー)

既定の設定は [`default-policy.toml`](core/src/main/resources/io/github/katyusha8138/mcc2s/default-policy.toml) にコメント付きで入っています。

```toml
mode = "audit"        # 導入時は audit で誤検知を洗い出し、問題なければ enforce に

[[mods.allow]]        # クライアント専用 Mod の許可(hash モードでは sha256 必須)
id = "sodium"
sha256 = ["<jar の SHA-256>"]
```

設定のタイプミス・曖昧な許可(hash モードで sha256 無し等)は、意図せず許可が広がらないよう起動時にエラーになります。
