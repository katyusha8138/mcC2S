#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
#
# NeoForge 1.21.1 の実機エンドツーエンド試験(開発環境の専用サーバー + 実クライアント)。
#
#   tools/e2e/e2e.sh [シナリオ...]     (省略時は全シナリオ)
#
# シナリオ:
#   vanilla   mcC2S を持たないクライアント(生プロトコルのプローブ)     -> 拒否される
#   trusted   信頼ファイルを持つ正規クライアント                          -> 通る
#   notrust   信頼ファイルが無いクライアント                              -> クライアントが案内付きで中止する
#   extrajar  mods/ に未登録の jar(隠し jar)を置いたクライアント        -> 拒否される
#   audit     audit モード + 隠し jar                                     -> 通る(違反はログに残る)
#
# 前提: Xvfb / Mesa(ソフトウェア GL)、Python 3。ネットワークは Gradle の依存取得にのみ使う。
# 重要: シナリオの途中で neoforge のビルド出力(build/classes)を変えないこと。
#       mcC2S 本体のハッシュ(自己測定)が変わり、サーバーとクライアントで食い違って拒否される。
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$ROOT/neoforge/run"
OUT="${E2E_OUT:-$ROOT/build/e2e}"
PORT=25599
mkdir -p "$OUT"
SERVER_LOG="$OUT/server.log"
PASS=0
FAIL=0

log() { echo "[e2e] $*"; }

# 実行ディレクトリで見分けて Java プロセスを止める(コマンドライン文字列では自分自身にマッチしてしまうため)
kill_game() {
  for pid in $(pgrep java 2>/dev/null); do
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
    case "$cwd" in
      "$RUN"/server|"$RUN"/client) kill "$pid" 2>/dev/null ;;
    esac
  done
  for _ in $(seq 1 30); do
    alive=0
    for pid in $(pgrep java 2>/dev/null); do
      cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
      case "$cwd" in "$RUN"/server|"$RUN"/client) alive=1 ;; esac
    done
    [ "$alive" = 0 ] && return 0
    sleep 1
  done
  log "WARN: game processes did not exit"
}

prepare() {
  mkdir -p "$RUN/server" "$RUN/client/config/mcc2s/trust" "$RUN/client/mods"
  echo "eula=true" > "$RUN/server/eula.txt"
  cat > "$RUN/server/server.properties" <<EOF
online-mode=false
server-port=$PORT
motd=mcC2S e2e
spawn-protection=0
max-players=5
view-distance=4
simulation-distance=4
EOF
  cat > "$RUN/client/options.txt" <<EOF
onboardAccessibility:false
tutorialStep:none
renderDistance:2
maxFps:15
fancyGraphics:false
enableVsync:false
skipMultiplayerWarning:true
soundCategory_master:0.0
EOF
  rm -f "$RUN/client/mods/"*.jar "$RUN/client/config/mcc2s/trust/"*.mc2strust
  rm -rf "$RUN/server/logs/mcc2s"
}

start_server() {
  local mode="$1"
  kill_game
  # ポリシー(mode)を指定して起動する。既存の識別鍵・pack_secret は再利用される。
  mkdir -p "$RUN/server/config/mcc2s"
  if [ -f "$RUN/server/config/mcc2s/policy.toml" ]; then
    sed -i "s/^mode = .*/mode = \"$mode\"/" "$RUN/server/config/mcc2s/policy.toml"
  fi
  rm -rf "$RUN/server/logs/mcc2s"
  : > "$SERVER_LOG"
  (cd "$ROOT" && nohup ./gradlew :neoforge:runServer --console=plain > "$SERVER_LOG" 2>&1 &)
  for _ in $(seq 1 180); do
    grep -q 'Done (' "$SERVER_LOG" && break
    grep -q 'Failed to start the minecraft server' "$SERVER_LOG" && { log "server failed to start"; tail -20 "$SERVER_LOG"; return 1; }
    sleep 2
  done
  grep -q 'Done (' "$SERVER_LOG" || { log "server did not start in time"; return 1; }
  # 初回起動時に policy.toml が生成される。mode を反映するため、生成直後の場合は再起動する。
  if ! grep -q "mode=$(echo "$mode" | tr a-z A-Z)" "$SERVER_LOG"; then
    log "policy mode differs from '$mode'; restarting once with the generated policy"
    kill_game
    sed -i "s/^mode = .*/mode = \"$mode\"/" "$RUN/server/config/mcc2s/policy.toml"
    : > "$SERVER_LOG"
    (cd "$ROOT" && nohup ./gradlew :neoforge:runServer --console=plain > "$SERVER_LOG" 2>&1 &)
    for _ in $(seq 1 180); do grep -q 'Done (' "$SERVER_LOG" && break; sleep 2; done
  fi
  grep -q 'Done (' "$SERVER_LOG"
}

install_trust() { cp -f "$RUN"/server/config/mcc2s/trust/*.mc2strust "$RUN/client/config/mcc2s/trust/"; }

# 実クライアントを起動し、サーバーが名前入りの判定ログを出すまで待つ。ログのパスは CLIENT_LOG に入る。
# (注意: コマンド置換 $(...) の中でバックグラウンド起動すると、子プロセスがパイプを握って戻らなくなる)
CLIENT_LOG=""
run_client() {
  local name="$1"
  CLIENT_LOG="$OUT/client-$name.log"
  : > "$CLIENT_LOG"
  {
    cd "$ROOT" && LIBGL_ALWAYS_SOFTWARE=1 exec xvfb-run -a -s "-screen 0 1280x720x24" \
      ./gradlew :neoforge:runClient -Pquickplay=127.0.0.1:$PORT -Pmcname="$name" --console=plain
  } > "$CLIENT_LOG" 2>&1 < /dev/null &
  for _ in $(seq 1 120); do
    if grep -qE "\[mcC2S\] $name verified|\[mcC2S\] (DENIED|AUDIT_ALLOWED) $name|$name joined the game|Client disconnected with reason" "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null; then
      sleep 4
      break
    fi
    sleep 3
  done
}

stop_client() {
  for pid in $(pgrep java 2>/dev/null); do
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
    [ "$cwd" = "$RUN/client" ] && kill "$pid" 2>/dev/null
  done
  sleep 4
}

expect() { # expect <説明> <ファイル> <正規表現>
  if grep -qE "$3" "$2" 2>/dev/null; then log "  PASS: $1"; PASS=$((PASS+1)); else log "  FAIL: $1  (pattern '$3' not found in $2)"; FAIL=$((FAIL+1)); fi
}
expect_not() {
  if grep -qE "$3" "$2" 2>/dev/null; then log "  FAIL: $1  (unexpected '$3' in $2)"; FAIL=$((FAIL+1)); else log "  PASS: $1"; PASS=$((PASS+1)); fi
}

scenario_vanilla() {
  log "== vanilla: client without mcC2S"
  python3 "$ROOT/tools/e2e/vanilla_probe.py" --port $PORT --name VanillaVic > "$OUT/vanilla.out" 2>&1
  cat "$OUT/vanilla.out" | sed 's/^/    /'
  expect "kicked with the mcC2S-required message" "$OUT/vanilla.out" "DISCONNECTED.*mcC2S"
  expect "server logged it" "$SERVER_LOG" "VanillaVic.*does not have mcC2S installed"
}

scenario_trusted() {
  log "== trusted: legitimate client with the trust file"
  install_trust
  run_client TrustedTim; local clog="$CLIENT_LOG"
  expect "server verified the client" "$SERVER_LOG" "\[mcC2S\] TrustedTim verified"
  expect "player joined the world" "$SERVER_LOG" "TrustedTim joined the game"
  expect_not "no violation reported" "$SERVER_LOG" "\[mcC2S\] DENIED TrustedTim"
  expect "client sent its inventory of files" "$clog" "\[mcC2S\] sending [0-9]+ entries"
  stop_client
}

scenario_notrust() {
  log "== notrust: client without the trust file"
  rm -f "$RUN/client/config/mcc2s/trust/"*.mc2strust
  run_client NoTrustNed; local clog="$CLIENT_LOG"
  expect "client aborted with a helpful message" "$clog" "Client disconnected with reason: .*信頼ファイル"
  expect_not "never joined" "$SERVER_LOG" "NoTrustNed joined the game"
  stop_client
}

scenario_extrajar() {
  log "== extrajar: unregistered jar in mods/"
  install_trust
  printf 'not a real mod' > "$RUN/client/mods/hidden-cheat-loader.jar"
  run_client SneakySam; local clog="$CLIENT_LOG"
  expect "server denied the client" "$SERVER_LOG" "\[mcC2S\] DENIED SneakySam"
  expect "the hidden jar was named in the server log" "$SERVER_LOG" "NOT_ALLOWED LIBRARY \[hidden-cheat-loader.jar\]"
  expect "client was disconnected" "$clog" "Client disconnected with reason: .*Unauthorized"
  expect_not "never joined" "$SERVER_LOG" "SneakySam joined the game"
  expect "JSON Lines record written" "$RUN/server/logs/mcc2s/violations.jsonl" "hidden-cheat-loader.jar"
  stop_client
}

scenario_audit() {
  log "== audit: violations are logged but the client is admitted"
  install_trust
  printf 'not a real mod' > "$RUN/client/mods/hidden-cheat-loader.jar"
  run_client AuditAmy; local clog="$CLIENT_LOG"
  expect "logged as AUDIT_ALLOWED" "$SERVER_LOG" "\[mcC2S\] AUDIT_ALLOWED AuditAmy"
  expect "player joined the world" "$SERVER_LOG" "AuditAmy joined the game"
  stop_client
}

main() {
  local scenarios=("$@")
  [ ${#scenarios[@]} -eq 0 ] && scenarios=(vanilla trusted notrust extrajar audit)
  prepare
  # 初回: policy.toml と信頼ファイルを生成させる
  start_server enforce || { log "cannot start the server"; exit 2; }
  local needs_audit=0
  for s in "${scenarios[@]}"; do
    if [ "$s" = audit ]; then needs_audit=1; continue; fi
    "scenario_$s"
  done
  if [ "$needs_audit" = 1 ]; then
    start_server audit || { log "cannot restart the server in audit mode"; exit 2; }
    scenario_audit
  fi
  kill_game
  log "result: $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}

main "$@"
