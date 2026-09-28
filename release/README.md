# release/

リリース署名に関するファイル置き場です。詳細は [docs/RELEASING.md](../docs/RELEASING.md)。

- `release-public-key.txt` — リリース署名鍵の**公開鍵**(base64url 1 行)。公開情報なのでコミットしてよい。
  このファイルがある状態でビルドすると、mod jar に同梱され、サーバーは署名付きの公式ビルド一覧
  (`official-builds.txt`)を検証できるようになる。無い場合は「サーバーと同一ビルドの mcC2S のみ許可」の厳格動作になる。
- **秘密鍵はここに置かない。** 秘密鍵ファイルは GitHub Actions のシークレット `MCC2S_RELEASE_KEY` と、
  オフラインの安全な保管場所にのみ置く。
