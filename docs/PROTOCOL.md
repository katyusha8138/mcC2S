# mcC2S プロトコル仕様 (v1)

実装は `core/src/main/java/io/github/katyusha8138/mcc2s/core/handshake/`。ここに書いてあることが正で、
コードが仕様と違う場合はバグです。

## 使用する暗号プリミティブ(JDK 標準 JCA のみ)

| 用途 | アルゴリズム |
|---|---|
| サーバー認証・リリース署名 | Ed25519 |
| 鍵共有 | X25519(全ゼロ出力は拒否) |
| 鍵導出 | HKDF-SHA256 (RFC 5869) |
| 暗号化+認証 | ChaCha20-Poly1305 (RFC 8439) |
| ハッシュ・測定証明 | SHA-256 / HMAC-SHA256 |

外部の暗号ライブラリには依存しません。ラベルはすべて `Labels.java` に集約し、ドメイン分離しています。

## 登場するもの

- **サーバー識別鍵**: サーバーの長期 Ed25519 鍵。秘密鍵はサーバーにのみ置く。
- **pack_secret**: サーバー別の 256bit 共有秘密。**信頼ファイル**に入れて Mod パックと一緒に配布する。
- **信頼ファイル**: `label` + サーバー公開鍵 + pack_secret + チェックサム(`mcc2s-trust-v1`)。
- **context**: ハンドシェイクを接続に束縛するバイト列。アダプタ(`common` の `Bindings.player`)は
  **ログイン名**を使う。オフラインモードのサーバーでは、サーバーが割り当てる UUID とクライアントの UUID が
  一致しないため UUID では束縛できないが、ログイン名は両側が必ず知っている。`Contexts.compose` で要素を追加できる(`PROXY.md`)。

## ハンドシェイク

```
S → C  Challenge   (Ed25519 署名付き)
C → S  Attestation (AEAD)
S → C  Verdict     (AEAD)
```

### Challenge (S→C)

```
u8  version = 1
u8  suite   = 1
[8] keyId            = SHA-256framed("mcC2S/v1 key-id", サーバー公開鍵)[0..8]
[32] ephemeralKey    (X25519 公開鍵)
[32] nonceS
u8  scopeMask        (報告を要求する範囲。MODS=1 RESOURCE_PACKS=2 SHADER_PACKS=4 JVM_AGENTS=8)
u8  proofRatePercent (0〜100)
[64] signature       = Ed25519_sign(サーバー鍵, framed("mcC2S/v1 challenge-sig", th1))
```
`th1 = framed("mcC2S/v1 th1", context, 署名前の全フィールド)`

クライアントは `keyId` で信頼ファイルを引き、**ピン留めされた公開鍵で署名を検証**する。
未知の keyId・署名不正・未対応の version/suite は応答せず破棄する(ダウングレード拒否)。

### Attestation (C→S)

```
u8  version = 1
[8] secretId   = HMAC(pack_secret, "mcC2S/v1 secret-id")[0..8]
[32] ephemeralKey  (X25519 公開鍵)
[32] nonceC
blob ciphertext
```
鍵導出:
```
ecdh = X25519(自分の一時秘密鍵, 相手の一時公開鍵)
th2  = framed("mcC2S/v1 th2", th1, version, secretId, C.ephemeralKey, nonceC)
prk  = HKDF-Extract(salt = nonceS || nonceC, ikm = ecdh || pack_secret)
k_c2s   = HKDF-Expand(prk, "mcC2S/v1 key c2s"   || th2, 32)
k_s2c   = HKDF-Expand(prk, "mcC2S/v1 key s2c"   || th2, 32)
k_proof = HKDF-Expand(prk, "mcC2S/v1 key proof" || th2, 32)
```
`ciphertext = ChaCha20-Poly1305(k_c2s, nonce=0, aad=th2, plaintext=Manifest)`。
1 つの鍵は 1 メッセージにしか使わない。

サーバーは 1 ハンドシェイクにつき **1 回だけ** `open` できる(失敗でも消費)。pack_secret が違う相手は
AEAD を通れず、マニフェストはパースされない。

### Verdict (S→C)

```
u8 version = 1
blob AEAD(k_s2c, nonce=0, aad=th3, plaintext = { u8 status, u16 reasonCode, [8] refId, str message, u32 reverifySeconds })
th3 = framed("mcC2S/v1 th3", th2, attestation ciphertext)
```
判定の強制力はサーバー側の切断にある。Verdict はクライアント UI 向けの案内と再検証間隔の通知。

## マニフェスト(平文。上限 2 MiB、4096 項目)

```
u8 formatVersion=1, str minecraftVersion, str loaderName, str loaderVersion, str mcC2SVersion
u8 reportedScopes
u16 count, 各項目: u8 kind, str id, str version, [32] sha256, u8 hasProof, [32] proof?
```

| kind | 内容 |
|---|---|
| MOD | FML が Mod として登録した jar |
| LIBRARY | `mods/` にあるが Mod として登録されない jar(隠し jar・ライブラリ) |
| RESOURCE_PACK | 有効な外部リソースパック(zip=ファイルハッシュ、フォルダ=ツリーハッシュ) |
| SHADER_PACK | 有効なシェーダーパック |
| AGENT | `-javaagent` / `-agentpath` で読み込まれたもの |
| OTHER_CODE | 上記以外のコード源 |
| SELF | mcC2S 本体(必須・1 件) |

文字列に制御文字を含む項目は拒否する。パス・ユーザー名・OS 等は含まない。

## 測定証明(セッション束縛)

```
proof = HMAC(k_proof, "mcC2S/v1 proof" || kind || sha256 || ファイルの全バイト)
```
サーバーが同じバイト列(自分の Mod・mcC2S 本体・`reference/` の jar)を持つ項目だけ検証できる。
どの項目に証明が必須かは `nonceS` から決まる決定的なサンプリング(割合 `proofRatePercent`)で、
クライアントは事前に予測できない。SELF は常に必須。

## 分割送信

Minecraft のサーバー行きカスタムペイロードは約 32KB なので、`Fragmenter` が
`{u8 type, u16 index, u16 total, blob data}` のチャンクに分ける(推奨 30,000 バイト/チャンク)。
`Reassembler` は順序外・重複・種別違い・総量超過・完了後の追加をすべて拒否する。

## 再検証(プレイ中)

`mcc2s:verify` は設定フェーズ(参加時の検証)とプレイフェーズの両方に登録される。プレイ中は、サーバーが
新しい `ServerHandshake`(新しい nonce・一時鍵)を作り、**同じ手順**でチャレンジを送る。判定の厳格さは
参加時と同じで、違反・無応答(既定 30 秒)・不正なデータはすべて切断する。

- **間隔**: 参加後、`[reverify] min_seconds`〜`max_seconds`(既定 300〜900 秒)のランダムな待ち時間で予約し、
  成功するたびに次回を予約する。同じ接続で重複して走ることはない
- **クライアントからの通知**: リソースの再読み込み(リソースパックの切替など)を検知したクライアントは、
  型 `TYPE_REVERIFY_REQUEST (4)` の空のチャンクを送る。サーバーは(`on_change = true` のとき)次の定期検証を
  待たずに再検証する。ただし連続実行の最小間隔(10 秒)で抑制され、通知を連打しても 1 回に集約される。
  通知は「早めてほしい」という**ヒントにすぎず**、送らなくても定期検証は行われる(通知を握りつぶす改造クライアントも捕捉できる)
- クライアントは、新しいチャレンジの先頭チャンク(型 CHALLENGE・index 0)が届くたびに検証を最初から作り直す

## 公式ビルド一覧

```
mcc2s-official-builds-v1
build <sha256> <version> <loader>
...
signature <base64url>      # Ed25519(リリース鍵, "mcC2S/v1 official-builds\n" || signature 行より前のテキスト)
```
サーバーは、クライアントが報告した SELF のハッシュがこの一覧(または自身のビルド)に含まれることを要求する。

## 定数と上限

| 項目 | 値 |
|---|---|
| マニフェスト平文 | ≤ 2 MiB、≤ 4096 項目 |
| id / version | ≤ 256 / 128 文字 |
| チャンク本体 | デコード時 ≤ 1 MiB |
| Verdict のメッセージ | ≤ 512 バイト |
