#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
#
# 本番と同じ構成(公式インストーラで入れたローダー + mods/ に配布 jar)を build/dist-run/<loader>/ に用意する。
# 開発実行(runServer / runClient)では、Forge 1.20.1 の本番用の名前(SRG)に再マッピングした jar も、
# 難読化した jar も動かせない。配布 jar そのものを動かして確かめるための土台。
#
#   tools/e2e/dist/setup.sh <forge|neoforge>
#
# 冪等: 済んでいる手順は飛ばす。ダウンロードは Forge / NeoForge / Mojang のホストへ行く。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
loader="${1:?usage: setup.sh <forge|neoforge>}"

case "$loader" in
  forge)
    installer_url="https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1-47.4.10/forge-1.20.1-47.4.10-installer.jar"
    java_bin="${JAVA17_HOME:-/opt/jdk17}/bin/java"
    ;;
  neoforge)
    installer_url="https://maven.neoforged.net/releases/net/neoforged/neoforge/21.1.252/neoforge-21.1.252-installer.jar"
    java_bin="${JAVA21_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}/bin/java"
    ;;
  *) echo "unknown loader: $loader" >&2; exit 2 ;;
esac
[ -x "$java_bin" ] || java_bin="$(command -v java)"

dir="$ROOT/build/dist-run/$loader"
mkdir -p "$dir/cache" "$dir/server" "$dir/client"
installer="$dir/cache/installer.jar"
if [ ! -s "$installer" ]; then
  echo "[dist] downloading the $loader installer"
  curl -fsSL --retry 5 --retry-delay 10 -o "$installer.part" "$installer_url"
  mv "$installer.part" "$installer"
fi

if [ ! -f "$dir/server/.installed" ]; then
  echo "[dist] installing the $loader server"
  (cd "$dir/server" && "$java_bin" -jar "$installer" --installServer . > "$dir/cache/install-server.log" 2>&1) \
    || { tail -20 "$dir/cache/install-server.log"; exit 1; }
  touch "$dir/server/.installed"
fi

if [ ! -f "$dir/client/.installed" ]; then
  echo "[dist] installing the $loader client"
  # クライアントのインストーラは、ランチャーのプロファイルファイルがあることを要求する
  [ -f "$dir/client/launcher_profiles.json" ] || echo '{"profiles":{},"version":3}' > "$dir/client/launcher_profiles.json"
  (cd "$dir/client" && "$java_bin" -jar "$installer" --installClient . > "$dir/cache/install-client.log" 2>&1) \
    || { tail -20 "$dir/cache/install-client.log"; exit 1; }
  touch "$dir/client/.installed"
fi

# バニラ側のバージョン JSON とライブラリ(インストーラは取得しない)を取得する。冪等。
echo "[dist] fetching the vanilla libraries for the $loader client"
python3 "$ROOT/tools/e2e/dist/launch_client.py" --dir "$dir/client" --name Setup --fetch-only
echo "[dist] $loader is ready in $dir"
