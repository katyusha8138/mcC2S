# mcC2S 実装計画

## 決定事項

| 項目 | 決定 |
|---|---|
| 対象 | **NeoForge 1.21.1 (Java 21)** を先行、続いて **Forge 1.20.1 (Java 17)** の二段構成 |
| 配布方式 | 汎用 jar + サーバー別の**信頼ファイル**(サーバー公開鍵 + pack_secret)。将来、プレイヤー別ビルド(ウォーターマーク)へ拡張可 |
| 公開/難読化 | OSS 公開 + Java レベルの難読化(秘密は鍵にのみ置く) |
| 検証範囲 | Mod + リソースパック + シェーダーパック + JVM エージェント/未登録コード源 |
| 適用範囲 | 専用サーバーのみ。シングルプレイ・LAN・mcC2S 未導入サーバーでは何もしない |

## 構成

```
core/      ローダー非依存(Java 17 API)。暗号・プロトコル・マニフェスト・ポリシー・設定・署名   ← M1 完了
common/    Minecraft 非依存の共通ロジック。走査・検証の状態機械・設定ファイル生成・違反ログ   ← M2 完了
neoforge/  NeoForge 1.21.1 アダプタ(設定フェーズの検証タスクに配線するだけの薄い層)          ← M2 完了
forge/     Forge 1.20.1 アダプタ                                                               ← M4
cli/       鍵生成・信頼ファイル生成・ハッシュ生成・リリース署名                                 ← M3
```

`core` は Minecraft に依存しないので単体でテストできる。アダプタは「Minecraft から情報を集める」
「切断する」「コンソールに出す」だけを担当する薄い層にする。

## マイルストーン

- **M1 `core`(完了)**: 暗号ハンドシェイク、マニフェスト、ポリシー評価、TOML 設定、違反報告、
  署名付き公式ビルド一覧、分割送信。攻撃シナリオのテスト(リプレイ・改ざん・ダウングレード・なりすまし等)。
- **M2 NeoForge アダプタ(完了)**: 設定フェーズ(ログイン認証後・プレイ開始前)で検証し、完了までワールドに入れない。
  ペイロードは optional 登録(未導入サーバーには影響なし、未導入クライアントはサーバー側で拒否)。専用サーバーのみ有効。
  Mod / 隠し jar / リソースパック / シェーダー / JVM エージェントを走査し、サーバー自身の Mod を baseline に、
  `reference/` の jar を測定証明の参照に使う。失敗・タイムアウト・内部エラーはすべて切断側に倒す。
  **実機 E2E**(NeoForge 21.1.252 の専用サーバー + 実クライアント、`tools/e2e/e2e.sh`)で、
  バニラ相当の拒否・正規クライアントの参加・信頼ファイル無しの案内付き中止・隠し jar の拒否・audit を確認済み。
- **M3 運用機能**: プレイ中の再検証、`/mcc2s reload|status|whitelist add`、CLI(`keygen`、`trustfile`、`hash`、
  `sign-release`)、署名付きリリースの CI、多言語メッセージ(ja/en)
- **M4 難読化 + Forge 1.20.1 アダプタ**: 難読化(名前・文字列)のビルド統合、Forge 用アダプタ

## 環境メモ

M2 以降のビルドには、Forge/NeoForge/Mojang の Maven・配布ホストへの到達が必要:
`maven.neoforged.net` / `maven.minecraftforge.net` / `piston-meta.mojang.com` / `piston-data.mojang.com` /
`libraries.minecraft.net`(許可済み)。

## 未決事項

- ライセンスは GPL-3.0-or-later で進行中(`docs/LICENSING.md`)。`or-later` か `only` かの最終確認
- リリース署名鍵の生成と保管(CI のシークレット)
- Velocity/BungeeCord 等のプロキシ経由サーバーへの対応(直結を想定。拡張余地は `docs/PROXY.md`)
