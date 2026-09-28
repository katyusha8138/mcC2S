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
# ソフトウェア描画は遅く、地形の読み込み前に落下死すると画面が開いてキー入力が効かなくなるため、死なないようにする
gamemode=creative
force-gamemode=true
difficulty=peaceful
EOF
  cat > "$RUN/client/options.txt" <<EOF
onboardAccessibility:false
tutorialStep:none
renderDistance:2
maxFps:15
fancyGraphics:false
enableVsync:false
skipMultiplayerWarning:true
pauseOnLostFocus:false
soundCategory_master:0.0
EOF
  rm -f "$RUN/client/mods/"*.jar "$RUN/client/config/mcc2s/trust/"*.mc2strust
  rm -rf "$RUN/server/logs/mcc2s"
}

# start_server <mode> [min_seconds max_seconds]
# ポリシー(mode と再検証の間隔)を指定して専用サーバーを起動する。既存の識別鍵・pack_secret は再利用される。
apply_policy() {
  local mode="$1" min="${2:-300}" max="${3:-900}"
  local f="$RUN/server/config/mcc2s/policy.toml"
  [ -f "$f" ] || return 0
  sed -i "s/^mode = .*/mode = \"$mode\"/; s/^min_seconds = .*/min_seconds = $min/; s/^max_seconds = .*/max_seconds = $max/" "$f"
}

boot_server() {
  : > "$SERVER_LOG"
  (cd "$ROOT" && nohup ./gradlew :neoforge:runServer --console=plain > "$SERVER_LOG" 2>&1 &)
  for _ in $(seq 1 180); do
    grep -q 'Done (' "$SERVER_LOG" && return 0
    grep -q 'Failed to start the minecraft server' "$SERVER_LOG" && { log "server failed to start"; tail -20 "$SERVER_LOG"; return 1; }
    sleep 2
  done
  log "server did not start in time"
  return 1
}

start_server() {
  local mode="$1" min="${2:-300}" max="${3:-900}"
  kill_game
  mkdir -p "$RUN/server/config/mcc2s"
  local first=0
  [ -f "$RUN/server/config/mcc2s/policy.toml" ] || first=1
  apply_policy "$mode" "$min" "$max"
  rm -rf "$RUN/server/logs/mcc2s"
  boot_server || return 1
  # policy.toml が無かった場合は今の起動で既定値のまま生成された。指定のプロファイルを反映するため 1 回だけ再起動する。
  if [ "$first" = 1 ]; then
    kill_game
    apply_policy "$mode" "$min" "$max"
    boot_server || return 1
  fi
  return 0
}

# FML がライブラリとして警告なしに読み込む jar(マニフェストに FMLModType)を作る。
# mods.toml の無い jar を置くと FML は警告画面を出してクライアントが先へ進まないため、
# 実際の攻撃(隠しライブラリ jar)と同じ形にしている。
make_plain_jar() {
  python3 - "$1" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("META-INF/MANIFEST.MF",
               "Manifest-Version: 1.0\r\nFMLModType: LIBRARY\r\nAutomatic-Module-Name: e2e.hiddenlib\r\n\r\n")
    z.writestr("hello.txt", "not a mod")
PY
}

install_trust() { cp -f "$RUN"/server/config/mcc2s/trust/*.mc2strust "$RUN/client/config/mcc2s/trust/"; }

# 実クライアントを起動し、サーバーが名前入りの判定ログを出すまで待つ。ログのパスは CLIENT_LOG に入る。
# (注意: コマンド置換 $(...) の中でバックグラウンド起動すると、子プロセスがパイプを握って戻らなくなる)
CLIENT_LOG=""
run_client() {
  local name="$1"
  CLIENT_LOG="$OUT/client-$name.log"
  : > "$CLIENT_LOG"
  # ログのファイルサイズを 40MB に制限する(FML の起動エラーで確認プロンプトが無限に出力されても、ディスクを埋めない)
  {
    ulimit -f 40960
    cd "$ROOT" && LIBGL_ALWAYS_SOFTWARE=1 exec xvfb-run -a -s "-screen 0 1280x720x24" \
      ./gradlew :neoforge:runClient -Pquickplay=127.0.0.1:$PORT -Pmcname="$name" --console=plain
  } > "$CLIENT_LOG" 2>&1 < /dev/null &
  for _ in $(seq 1 60); do
    if grep -q "y/n:" "$CLIENT_LOG" 2>/dev/null; then log "  client crashed during startup (see $CLIENT_LOG)"; break; fi
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

# ログはプロセス間を経由して少し遅れて書かれるため、最大 15 秒リトライして判定する
wait_for() { # wait_for <ファイル> <正規表現>
  for _ in $(seq 1 15); do
    grep -qE "$2" "$1" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
expect() { # expect <説明> <ファイル> <正規表現>
  if wait_for "$2" "$3"; then log "  PASS: $1"; PASS=$((PASS+1)); else log "  FAIL: $1  (pattern '$3' not found in $2)"; FAIL=$((FAIL+1)); fi
}
expect_not() { # 一定時間待っても現れないこと
  sleep 3
  if grep -qE "$3" "$2" 2>/dev/null; then log "  FAIL: $1  (unexpected '$3' in $2)"; FAIL=$((FAIL+1)); else log "  PASS: $1"; PASS=$((PASS+1)); fi
}

# 実行中の Xvfb のディスプレイ番号(":99" など)を返す
xvfb_display() {
  pgrep -a Xvfb 2>/dev/null | grep -o ' :[0-9]*' | head -1 | tr -d ' '
}

# xvfb-run が使っている X の認証ファイル(-auth の値)。これが無いと仮想ディスプレイに接続できない。
xvfb_auth() {
  pgrep -a Xvfb 2>/dev/null | grep -o -- '-auth [^ ]*' | head -1 | cut -d' ' -f2
}

# 仮想ディスプレイへのキー入力に python-xlib を使う(無ければ build/pylib に入れる)。使えなければ 1 を返す。
ensure_xlib() {
  export PYTHONPATH="$ROOT/build/pylib${PYTHONPATH:+:$PYTHONPATH}"
  python3 -c 'import Xlib' 2>/dev/null && return 0
  mkdir -p "$ROOT/build/pylib"
  python3 -m pip install --quiet --target "$ROOT/build/pylib" python-xlib >/dev/null 2>&1
  python3 -c 'import Xlib' 2>/dev/null
}

# 指定秒数まで待って判定する(定期再検証のように時間のかかる事象用)
expect_within() { # expect_within <秒> <説明> <ファイル> <正規表現>
  local secs="$1"
  for _ in $(seq 1 "$secs"); do
    grep -qE "$4" "$3" 2>/dev/null && { log "  PASS: $2"; PASS=$((PASS+1)); return 0; }
    sleep 1
  done
  log "  FAIL: $2  (pattern '$4' not found in $3 within ${secs}s)"; FAIL=$((FAIL+1))
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
  make_plain_jar "$RUN/client/mods/hidden-cheat-loader.jar"
  run_client SneakySam; local clog="$CLIENT_LOG"
  expect "server denied the client" "$SERVER_LOG" "\[mcC2S\] DENIED SneakySam"
  expect "the hidden jar was named in the server log" "$SERVER_LOG" "NOT_ALLOWED LIBRARY \[hidden-cheat-loader.jar\]"
  expect "client was disconnected with the denial message" "$clog" "Client disconnected with reason: \[mcC2S\] 許可されていない"
  expect_not "never joined" "$SERVER_LOG" "SneakySam joined the game"
  expect "JSON Lines record written" "$RUN/server/logs/mcc2s/violations.jsonl" "hidden-cheat-loader.jar"
  stop_client
}

scenario_audit() {
  log "== audit: violations are logged but the client is admitted"
  install_trust
  make_plain_jar "$RUN/client/mods/hidden-cheat-loader.jar"
  run_client AuditAmy; local clog="$CLIENT_LOG"
  expect "logged as AUDIT_ALLOWED" "$SERVER_LOG" "\[mcC2S\] AUDIT_ALLOWED AuditAmy"
  expect "player joined the world" "$SERVER_LOG" "AuditAmy joined the game"
  stop_client
}

scenario_reverify() {
  log "== reverify: periodic re-verification while playing (interval 30-35s)"
  install_trust
  run_client ReverifyRae; local clog="$CLIENT_LOG"
  expect "joined the world" "$SERVER_LOG" "ReverifyRae joined the game"
  expect_within 90 "the server re-verified the player during play" "$SERVER_LOG" "\[mcC2S\] ReverifyRae re-verified"
  # 参加後に隠しライブラリ jar を置く(ログイン後に導入されたチートを想定)
  make_plain_jar "$RUN/client/mods/late-cheat-loader.jar"
  expect_within 90 "the late-installed jar was detected by the next re-verification" "$SERVER_LOG" "\[mcC2S\] DENIED ReverifyRae"
  expect "the jar was named in the server log" "$SERVER_LOG" "NOT_ALLOWED LIBRARY \[late-cheat-loader.jar\]"
  expect "the player was kicked out of the running game" "$clog" "Client disconnected with reason: \[mcC2S\] 許可されていない"
  stop_client
}

scenario_onchange() {
  log "== onchange: a resource reload (e.g. switching resource packs) triggers an immediate re-verification"
  if ! ensure_xlib; then
    log "  SKIP: python-xlib is not available (pip install python-xlib)"
    return 0
  fi
  install_trust
  run_client OnChangeOli; local clog="$CLIENT_LOG"
  expect "joined the world" "$SERVER_LOG" "OnChangeOli joined the game"
  local disp; disp=$(xvfb_display)
  # 診断: 参加の数秒後と、キー入力の前の画面(死亡画面などでキーが効かない場合の切り分け用)
  sleep 4
  XAUTHORITY="$(xvfb_auth)" python3 "$ROOT/tools/e2e/screenshot.py" "$disp" "$OUT/onchange-join.png" 2>/dev/null
  local before; before=$(grep -c "Reloading ResourceManager" "$clog")
  # ソフトウェア描画は遅く、参加直後は「地形を読み込み中」でキーが効かないため、リソースが再読み込みされるまで 5 秒おきに押し直す
  local reloaded=0
  for attempt in $(seq 1 12); do
    sleep 5
    XAUTHORITY="$(xvfb_auth)" python3 "$ROOT/tools/e2e/keypress.py" "$disp" F3+t >/dev/null 2>&1
    sleep 2
    if [ "$(grep -c "Reloading ResourceManager" "$clog")" -gt "$before" ]; then reloaded=1; log "  (F3+T took effect on attempt $attempt)"; break; fi
  done
  if [ "$reloaded" = 1 ]; then log "  PASS: the reload really happened on the client (F3+T)"; PASS=$((PASS+1))
  else
    log "  FAIL: F3+T did not trigger a resource reload on the client"; FAIL=$((FAIL+1))
    XAUTHORITY="$(xvfb_auth)" python3 "$ROOT/tools/e2e/screenshot.py" "$disp" "$OUT/onchange-screen.png" 2>/dev/null && log "  screenshot: $OUT/onchange-screen.png"
  fi
  # 定期検証(600 秒以上)ではなく、リソース再読み込みの通知で再検証されたことを確かめる
  expect_within 40 "the server re-verified the player right after the reload notification" "$SERVER_LOG" "\\[mcC2S\\] OnChangeOli re-verified"
  stop_client
}

# シナリオごとに必要なサーバー設定(プロファイル)。プロファイルが変わるときだけサーバーを再起動する。
profile_of() {
  case "$1" in
    audit) echo "audit 300 900" ;;
    reverify) echo "enforce 30 35" ;;
    onchange) echo "enforce 600 900" ;;
    *) echo "enforce 300 900" ;;
  esac
}

main() {
  local scenarios=("$@")
  [ ${#scenarios[@]} -eq 0 ] && scenarios=(vanilla trusted notrust extrajar reverify onchange audit)
  prepare
  local current=""
  for s in "${scenarios[@]}"; do
    local profile; profile=$(profile_of "$s")
    if [ "$profile" != "$current" ]; then
      # shellcheck disable=SC2086
      start_server $profile || { log "cannot start the server for '$s' ($profile)"; exit 2; }
      current="$profile"
    fi
    "scenario_$s"
  done
  kill_game
  log "result: $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}

main "$@"
