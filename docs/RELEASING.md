# リリース手順(リリース担当向け)

公式ビルドの改ざん・偽造を検出する仕組み(`PROTOCOL.md` の「公式ビルド一覧」)のために、リリースは
**あなたが管理する Ed25519 署名鍵**で署名します。秘密鍵をリポジトリ・チャット・メールに載せないでください。

## 1. 署名鍵を作る(初回のみ)

```sh
./gradlew :cli:jar
java -jar cli/build/libs/mcc2s-cli-*.jar keygen --out release-key.identity
```

出力される「公開鍵(base64url)」を控えます(あとから `pubkey --identity release-key.identity` でも表示できます)。

1. **公開鍵をコミットする**: `release/release-public-key.txt` に 1 行で保存してコミットします(公開情報)。
   次のビルドから、mod jar に同梱され、サーバーが公式ビルド一覧を検証できるようになります。
2. **秘密鍵を GitHub に登録する**: `release-key.identity` の中身をそのまま、リポジトリの
   Settings → Secrets and variables → Actions に **`MCC2S_RELEASE_KEY`** として登録します。
3. **秘密鍵をオフラインでバックアップする**(パスワードマネージャや暗号化ストレージ)。
   失うと、それ以降のリリースを同じ鍵で署名できません(下記「鍵の更新」参照)。
4. ローカルの `release-key.identity` は、登録とバックアップが済んだら削除してください。
5. **タグを保護する**: Settings → Rules で `v*` タグの作成を管理者のみに制限します
   (タグの push で署名処理が動くため)。

## 2. リリースする

```sh
git tag v0.2.0
git push origin v0.2.0
```

`.github/workflows/release.yml` が次を行います。

1. `release/release-public-key.txt` があることを確認(無ければ失敗)
2. ビルドとテスト(`./gradlew build :cli:jar`)。JDK は 17(forge / Minecraft 1.20.1)と 21(neoforge / 1.21.1)の両方が要る。
   `build` は全モジュールのテストと、**配布 jar(難読化済み)** の生成を含む(下記「難読化」)
3. **公式ビルド一覧への署名**: 前回リリースの `official-builds.txt` があれば、署名を検証した上で引き継ぎ
   (追記専用)、今回の **NeoForge 用・Forge 用の配布 jar のハッシュ** を追加して署名(ローダーごとに 1 回ずつ)
4. 署名が、コミット済みの公開鍵で検証できることを確認
5. GitHub Release に、`mcc2s-neoforge-1.21.1-<版>.jar`・`mcc2s-forge-1.20.1-<版>.jar`・CLI jar・
   `official-builds.txt` を添付。難読化のマッピングは、公開のリリースではなくワークフローの成果物として保管する

配布物は **難読化後の jar**(`build/libs/<名前>-<版>.jar`)だけです。`...-plain.jar` は難読化前の中間物なので配布しません
(サーバーが照合する公式ビルドのハッシュは、配布する jar のものです)。

## 3. サーバー運営者に伝えること

- 新しいバージョンの mod jar と、**同じリリースの `official-builds.txt`** を配布する
- サーバーの `config/mcc2s/official-builds.txt` に置き、`/mcc2s reload`(または再起動)
- これで、そのリリースに含まれる**すべての公式ビルド**の mcC2S を持つクライアントが許可される
  (サーバーのビルドと一致していなくてもよい)

## 4. ビルドの再現性

ビルドは再現可能です(アーカイブのタイムスタンプ・順序を固定)。同じソース・同じ JDK・同じ Gradle
からは同じバイト列の jar ができるため、第三者が公式ビルドのハッシュを検証できます。

```sh
java -jar mcc2s-cli.jar hash neoforge/build/libs/mcc2s-neoforge-1.21.1-<版>.jar forge/build/libs/mcc2s-forge-1.20.1-<版>.jar
java -jar mcc2s-cli.jar verify-release --pubkey release/release-public-key.txt official-builds.txt
```

## 4.5 難読化

配布 jar は、`obfuscator`(文字列定数)と ProGuard(クラス・メソッド・フィールドの名前)で難読化されます
(`gradle/obfuscation.gradle`、設定は `gradle/proguard/`)。GPL の方針として、難読化するのは**配布する jar だけ**で、
ソースとビルドスクリプトは公開のままです(`LICENSING.md`)。

- 出力は入力だけで決まる(乱数・時刻を使わない)ので、難読化を含めてビルドは再現できる
- 難読化の対象は `core` / `common`(プロトコル・走査・検証)。ローダーとの接点(アダプタ)は名前を保つ
- 名前が残るのは、アダプタと例外クラス(診断メッセージに出るため)だけ
- 文字列連結の定型文も対象にするため、`core` / `common` は `-XDstringConcat=inline` でコンパイルする
- **限界**: 難読化は jar 単体を眺めて構造を読み取る手間を増やすだけ。ソースは公開で、再現可能ビルドなので
  マッピングも誰でも再生成できる。暗号・検証の安全性はこれに依存しない(`THREAT_MODEL.md`)

配布 jar は、開発実行ではなく**本番構成**で試験する(`E2E_DIST=1 tools/e2e/e2e.sh`、`tools/e2e/dist/`)。
Forge 1.20.1 の jar は本番用の名前(SRG)に再マッピングされていて、開発実行では動かせないため。

## 5. 鍵の更新(漏洩・紛失時)

署名鍵を更新する場合は、新しい鍵で 1. をやり直し、公開鍵を差し替えたビルドをリリースします。
**古い公開鍵を埋め込んだ古いビルドは、新しい鍵の署名を検証できません**ため、サーバー運営者には
新しい mod jar への更新が必要になります。漏洩した鍵で署名された一覧は、新しいビルドでは拒否されます。

## 開発者向け: 鍵なしビルド

`release/release-public-key.txt` が無い状態でビルドしても動きます(署名検証が無効になり、
サーバーは「自分と同一ビルドの mcC2S を持つクライアントのみ許可」する厳格な動作になります)。
