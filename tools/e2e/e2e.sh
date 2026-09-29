#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
#
# 実機エンドツーエンド試験(開発環境の専用サーバー + 実クライアント)。
#
#   tools/e2e/e2e.sh [シナリオ...]                    (省略時は全シナリオ。既定は NeoForge 1.21.1)
#   E2E_LOADER=forge tools/e2e/e2e.sh [シナリオ...]   Forge 1.20.1 を試験する(JDK 17 が必要)
#   E2E_DIST=1 [E2E_LOADER=forge] tools/e2e/e2e.sh    開発実行ではなく、配布 jar(難読化済み)そのものを試験する。
#       公式インストーラで入れた本番構成のサーバーとクライアントの mods/ に、build/libs の配布 jar を入れて動かす
#       (tools/e2e/dist/setup.sh が用意する。開発実行では、SRG 名に再マッピングした jar も難読化した jar も動かせない)
#
# シナリオ:
#   vanilla   mcC2S を持たないクライアント(生プロトコルのプローブ)     -> 拒否される
#   trusted   信頼ファイルを持つ正規クライアント                          -> 通る
#   notrust   信頼ファイルが無いクライアント                              -> クライアントが案内付きで中止する
#   extrajar  mods/ に未登録の jar(隠し jar)を置いたクライアント        -> 拒否される
#   reverify  プレイ中の定期再検証(参加後に隠し jar を置く)              -> 次の再検証で検出されて切断される
#   onchange  リソース再読み込み(F3+T)の通知による即時再検証            -> 定期間隔を待たずに再検証される
#   audit     audit モード + 隠し jar                                     -> 通る(違反はログに残る)
#
# 各シナリオはクライアントの mods/ と信頼ファイルを空にしてから始まる(前のシナリオの影響を受けない)。
#
# 前提: Xvfb / Mesa(ソフトウェア GL)、Python 3。ネットワークは Gradle の依存取得にのみ使う。
# 重要: シナリオの途中で neoforge のビルド出力(build/classes)を変えないこと。
#       mcC2S 本体のハッシュ(自己測定)が変わり、サーバーとクライアントで食い違って拒否される。
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOADER="${E2E_LOADER:-neoforge}"
case "$LOADER" in
  neoforge) PROTOCOL=767; PORT=25599 ;;   # Minecraft 1.21.1
  forge)    PROTOCOL=763; PORT=25598 ;;   # Minecraft 1.20.1
  *) echo "E2E_LOADER must be neoforge or forge (got '$LOADER')" >&2; exit 2 ;;
esac
DIST="${E2E_DIST:-0}"
if [ "$DIST" = 1 ]; then
  RUN="$ROOT/build/dist-run/$LOADER"
  OUT="${E2E_OUT:-$ROOT/build/e2e/dist-$LOADER}"
  case "$LOADER" in
    forge)    JAVA_BIN="${JAVA17_HOME:-/opt/jdk17}/bin/java" ;;
    neoforge) JAVA_BIN="${JAVA21_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}/bin/java" ;;
  esac
  [ -x "$JAVA_BIN" ] || JAVA_BIN="$(command -v java)"
else
  RUN="$ROOT/$LOADER/run"
  OUT="${E2E_OUT:-$ROOT/build/e2e/$LOADER}"
fi
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

# 配布 jar(難読化済み)をビルドし、サーバーとクライアントの mods/ に入れる。...-plain.jar は難読化前なので使わない。
install_dist_jar() {
  (cd "$ROOT" && ./gradlew ":$LOADER:distJar" --console=plain -q) || { log "distJar failed"; return 1; }
  local jar; jar="$(ls "$ROOT/$LOADER/build/libs/"mcc2s-"$LOADER"-*.jar | grep -v -- '-plain\.jar$' | head -1)"
  [ -n "$jar" ] || { log "no distribution jar found"; return 1; }
  mkdir -p "$RUN/server/mods" "$RUN/client/mods"
  rm -f "$RUN/server/mods/"mcc2s-*.jar "$RUN/client/mods/"mcc2s-*.jar
  cp "$jar" "$RUN/server/mods/"
  cp "$jar" "$RUN/client/mods/"
  log "distribution jar: $(basename "$jar") ($(sha256sum "$jar" | cut -c1-16)...)"
}

# クライアントの mods/ から、mcC2S 自身以外の jar(前のシナリオが置いたもの)を消す
clean_client_mods() {
  find "$RUN/client/mods" -maxdepth 1 -name '*.jar' ! -name 'mcc2s-*' -delete 2>/dev/null || true
}

prepare() {
  if [ "$DIST" = 1 ]; then
    "$ROOT/tools/e2e/dist/setup.sh" "$LOADER" || { log "setup failed"; exit 2; }
    install_dist_jar || exit 2
  fi
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
  clean_client_mods
  rm -f "$RUN/client/config/mcc2s/trust/"*.mc2strust
  rm -rf "$RUN/server/logs/mcc2s"
  # 前回までの実行で保存されたプレイヤーデータを消す。死亡したまま切断すると体力 0 の状態が保存され、
  # 同じ名前で再参加しても死亡画面から始まってキー入力が効かなくなる。
  rm -rf "$RUN/server/world/playerdata" "$RUN/server/world/stats" "$RUN/server/world/advancements"
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
  if [ "$DIST" = 1 ]; then
    # インストーラが作る起動引数(run.sh と同じ)で、本番と同じ形で起動する
    local args; args="$(ls "$RUN"/server/libraries/net/*/*/*/unix_args.txt | head -1)"
    [ -f "$RUN/server/user_jvm_args.txt" ] && ! grep -q '^-Xmx' "$RUN/server/user_jvm_args.txt" && echo "-Xmx1G" >> "$RUN/server/user_jvm_args.txt"
    (cd "$RUN/server" && nohup "$JAVA_BIN" @user_jvm_args.txt "@${args#$RUN/server/}" nogui > "$SERVER_LOG" 2>&1 &)
  else
    (cd "$ROOT" && nohup ./gradlew :$LOADER:runServer --console=plain > "$SERVER_LOG" 2>&1 &)
  fi
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
    cd "$ROOT"
    if [ "$DIST" = 1 ]; then
      LIBGL_ALWAYS_SOFTWARE=1 exec xvfb-run -a -s "-screen 0 1280x720x24" \
        python3 "$ROOT/tools/e2e/dist/launch_client.py" --dir "$RUN/client" --name "$name" \
          --quickplay "127.0.0.1:$PORT" --java "$JAVA_BIN"
    else
      LIBGL_ALWAYS_SOFTWARE=1 exec xvfb-run -a -s "-screen 0 1280x720x24" \
        ./gradlew :$LOADER:runClient -Pquickplay=127.0.0.1:$PORT -Pmcname="$name" --console=plain
    fi
  } > "$CLIENT_LOG" 2>&1 < /dev/null &
  for _ in $(seq 1 60); do
    if grep -q "y/n:" "$CLIENT_LOG" 2>/dev/null; then log "  client crashed during startup (see $CLIENT_LOG)"; break; fi
    if grep -qE "\[mcC2S\] $name verified|\[mcC2S\] (DENIED|AUDIT_ALLOWED) $name|$name joined the game|Client disconnected with reason|\[mcC2S\] disconnecting" "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null; then
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
expect() { # expect <説明> <ファイル> <正規表現>   (成功なら 0、失敗なら 1 を返す)
  if wait_for "$2" "$3"; then log "  PASS: $1"; PASS=$((PASS+1)); return 0; fi
  log "  FAIL: $1  (pattern '$3' not found in $2)"; FAIL=$((FAIL+1)); return 1
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

# サーバーが送った切断理由をクライアントが受け取ったことの確認。
#   NeoForge 1.21.1 のクライアントは "Client disconnected with reason: <理由>" をログに出す。
#   Forge 1.20.1 のクライアントは理由をログに出さないので、サーバー側の切断ログ("... lost connection: <理由>")で確認する。
expect_kick() { # expect_kick <説明> <プレイヤー名> <クライアントログ> <理由の一部>
  if [ "$LOADER" = forge ]; then
    expect "$1" "$SERVER_LOG" "(name=$2,|$2 lost connection).*$4"
  else
    expect "$1" "$3" "Client disconnected with reason: $4"
  fi
}

# 仮想ディスプレイの画面を保存する(目視確認用。失敗しても試験には影響しない)
snap() { # snap <名前>
  ensure_xlib || return 0
  local disp; disp=$(xvfb_display)
  [ -n "$disp" ] || return 0
  XAUTHORITY="$(xvfb_auth)" python3 "$ROOT/tools/e2e/screenshot.py" "$disp" "$OUT/$1.png" >/dev/null 2>&1 || true
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
  python3 "$ROOT/tools/e2e/vanilla_probe.py" --port $PORT --protocol $PROTOCOL --name VanillaVic > "$OUT/vanilla.out" 2>&1
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
  snap notrust
  expect "client aborted with a helpful message" "$clog" "(Client disconnected with reason: |\\[mcC2S\\] disconnecting: ).*信頼ファイル"
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
  snap extrajar
  expect_kick "client was disconnected with the denial message" SneakySam "$clog" "\[mcC2S\] 許可されていない"
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
  # 参加できていなければ、以降の判定(特に「後から入れた jar を再検証で検出」)は意味を持たないので打ち切る
  if ! expect "joined the world" "$SERVER_LOG" "ReverifyRae joined the game"; then stop_client; return 0; fi
  expect_within 90 "the server re-verified the player during play" "$SERVER_LOG" "\[mcC2S\] ReverifyRae re-verified"
  # 参加後に隠しライブラリ jar を置く(ログイン後に導入されたチートを想定)
  make_plain_jar "$RUN/client/mods/late-cheat-loader.jar"
  expect_within 90 "the late-installed jar was detected by the next re-verification" "$SERVER_LOG" "\[mcC2S\] DENIED ReverifyRae"
  expect "the jar was named in the server log" "$SERVER_LOG" "NOT_ALLOWED LIBRARY \[late-cheat-loader.jar\]"
  snap reverify
  expect_kick "the player was kicked out of the running game" ReverifyRae "$clog" "\[mcC2S\] 許可されていない"
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
  if ! expect "joined the world" "$SERVER_LOG" "OnChangeOli joined the game"; then stop_client; return 0; fi
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
    # 各シナリオは、前のシナリオがクライアントの mods/ に置いた jar を引き継がない(隔離)。
    # 信頼ファイルもここで外し、必要なシナリオが install_trust で入れ直す。
    clean_client_mods
    rm -f "$RUN/client/config/mcc2s/trust/"*.mc2strust
    "scenario_$s"
    # サーバーのログは、プロファイルが変わるたびの再起動で上書きされる。原因調査のためにシナリオごとに残す。
    cp -f "$SERVER_LOG" "$OUT/server-$s.log" 2>/dev/null || true
  done
  kill_game
  log "result: $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}

main "$@"
