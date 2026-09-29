#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
"""
公式インストーラで入れた Forge / NeoForge のクライアントを、ランチャー無しで起動する(試験用)。

ランチャーがやること(バージョン JSON の解釈)だけを行う:
  - versions/<id>/<id>.json と、inheritsFrom の親(バニラ)の JSON を合成する
  - libraries を OS のルールで選び、クラスパスを作る
  - JVM 引数・ゲーム引数のテンプレートを置換する
インストーラは、バニラ側のバージョン JSON とライブラリ(LWJGL など)を取得しない(それはランチャーの仕事)ので、
足りないものは Mojang のホスト(piston-meta.mojang.com / libraries.minecraft.net)から取得する。
認証はしない(オフラインのテストサーバーに接続するだけ)。アセットは指定のディレクトリを使う。

  launch_client.py --dir <クライアントのディレクトリ> --name <名前> [--quickplay host:port]
                   [--assets-dir <アセット>] [--java <java>] [--dry-run] [--fetch-only]

--dir にはインストーラの出力(versions/ と libraries/)と、ゲームのディレクトリを兼ねる。
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from pathlib import Path

MANIFEST_URL = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"


def download(url: str, dest: Path, sha1: str = "") -> None:
    """curl で取得する(環境のプロキシ・CA 設定をそのまま使えるため)。sha1 が分かっていれば検証する。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    subprocess.run(["curl", "-fsSL", "--retry", "5", "--retry-delay", "5", "-o", str(part), url], check=True)
    if sha1:
        got = hashlib.sha1(part.read_bytes()).hexdigest()
        if got != sha1:
            part.unlink()
            raise RuntimeError(f"sha1 mismatch for {url}: {got} != {sha1}")
    part.replace(dest)


def ensure_vanilla_json(base: Path, mc_version: str) -> None:
    path = base / "versions" / mc_version / f"{mc_version}.json"
    if path.is_file():
        return
    manifest_file = base / "versions" / ".version_manifest_v2.json"
    download(MANIFEST_URL, manifest_file)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    entry = next(v for v in manifest["versions"] if v["id"] == mc_version)
    download(entry["url"], path, entry.get("sha1", ""))


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def os_name() -> str:
    return {"Linux": "linux", "Darwin": "osx", "Windows": "windows"}.get(platform.system(), "linux")


def rule_allows(rules, features=None) -> bool:
    """Mojang のルール: 一致する最後の規則の action が有効。規則が無ければ許可。"""
    if not rules:
        return True
    allowed = False
    for r in rules:
        ok = True
        if "os" in r:
            o = r["os"]
            if "name" in o and o["name"] != os_name():
                ok = False
            if "arch" in o and o["arch"] not in ("x86_64", "amd64") and platform.machine() in ("x86_64", "AMD64"):
                ok = False
        if "features" in r:
            for k, v in r["features"].items():
                if bool((features or {}).get(k, False)) != v:
                    ok = False
        if ok:
            allowed = r.get("action") == "allow"
    return allowed


def maven_path(name: str) -> str:
    """group:artifact:version[:classifier][@ext] → リポジトリ内の相対パス"""
    ext = "jar"
    if "@" in name:
        name, ext = name.split("@", 1)
    parts = name.split(":")
    group, artifact, version = parts[0], parts[1], parts[2]
    classifier = "-" + parts[3] if len(parts) > 3 else ""
    return f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}{classifier}.{ext}"


def lib_key(name: str) -> str:
    parts = name.split("@")[0].split(":")
    return ":".join(parts[:2] + parts[3:4])  # バージョンを除いた識別子(クラスパスの重複除去用)


def resolve_version(base: Path, version_id: str) -> dict:
    """子の JSON に、親(inheritsFrom)の JSON を合成して返す。"""
    child = load_json(base / "versions" / version_id / f"{version_id}.json")
    parent_id = child.get("inheritsFrom")
    if not parent_id:
        child["_jar_id"] = version_id
        return child
    ensure_vanilla_json(base, parent_id)
    parent = resolve_version(base, parent_id)
    merged = dict(parent)
    for k, v in child.items():
        if k in ("libraries", "arguments", "inheritsFrom"):
            continue
        merged[k] = v
    merged["libraries"] = parent.get("libraries", []) + child.get("libraries", [])
    pa, ca = parent.get("arguments", {}), child.get("arguments", {})
    merged["arguments"] = {
        "jvm": pa.get("jvm", []) + ca.get("jvm", []),
        "game": pa.get("game", []) + ca.get("game", []),
    }
    # クラスパスに入れる「クライアント jar」は、起動するバージョン自身のもの(JSON に "jar" があればそれ)。
    # Forge / NeoForge は、インストーラが作った再マッピング済みのクライアントを libraries から読み込むので、
    # バニラの jar を入れてはいけない(モジュールが衝突する)。自身の jar は無いので、実際には何も入らない。
    merged["_jar_id"] = child.get("jar", version_id)
    return merged


def expand_args(entries, subst, features):
    out = []
    for e in entries:
        if isinstance(e, str):
            values = [e]
        else:
            if not rule_allows(e.get("rules"), features):
                continue
            v = e["value"]
            values = [v] if isinstance(v, str) else list(v)
        for s in values:
            for k, v in subst.items():
                s = s.replace("${" + k + "}", v)
            out.append(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--quickplay", default="")
    ap.add_argument("--assets-dir", default=os.environ.get("E2E_ASSETS_DIR", "/root/.gradle/caches/neoformruntime/assets"))
    ap.add_argument("--java", default="java")
    ap.add_argument("--version-id", default="", help="省略時は versions/ にある(バニラ以外の)唯一のバージョン")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--fetch-only", action="store_true", help="足りないファイルを取得して終わる(起動しない)")
    args = ap.parse_args()

    base = Path(args.dir).resolve()
    vid = args.version_id
    if not vid:
        cands = [p.name for p in (base / "versions").iterdir()
                 if p.is_dir() and (p / f"{p.name}.json").is_file()
                 and load_json(p / f"{p.name}.json").get("inheritsFrom")]
        if len(cands) != 1:
            print(f"cannot decide the version to launch: {cands}", file=sys.stderr)
            return 2
        vid = cands[0]
    v = resolve_version(base, vid)

    libs, seen = [], set()
    for lib in reversed(v["libraries"]):  # 子が親を上書きする
        if not rule_allows(lib.get("rules")):
            continue
        key = lib_key(lib["name"])
        if key in seen:
            continue
        seen.add(key)
        art = lib.get("downloads", {}).get("artifact")
        rel = art["path"] if art and art.get("path") else maven_path(lib["name"])
        p = base / "libraries" / rel
        if not p.is_file():
            if art and art.get("url"):
                download(art["url"], p, art.get("sha1", ""))
            elif art:
                continue  # インストーラが生成する成果物などで、取得元が無いエントリは飛ばす
            else:
                print(f"missing library: {p}", file=sys.stderr)
                return 2
        libs.append(str(p))
    libs.reverse()
    client_jar = base / "versions" / v["_jar_id"] / f"{v['_jar_id']}.jar"
    classpath_items = libs + ([str(client_jar)] if client_jar.is_file() else [])

    if args.fetch_only:
        print(f"ready: {len(libs)} libraries for {vid}")
        return 0
    natives = base / "natives"
    natives.mkdir(exist_ok=True)
    uid = str(uuid.uuid3(uuid.NAMESPACE_DNS, "OfflinePlayer:" + args.name))
    subst = {
        "natives_directory": str(natives),
        "launcher_name": "mcc2s-e2e",
        "launcher_version": "1",
        "classpath": os.pathsep.join(classpath_items),
        "classpath_separator": os.pathsep,
        "library_directory": str(base / "libraries"),
        "version_name": vid,
        "version_type": v.get("type", "release"),
        "game_directory": str(base),
        "assets_root": args.assets_dir,
        "assets_index_name": v["assetIndex"]["id"],
        "auth_player_name": args.name,
        "auth_uuid": uid,
        "auth_access_token": "0",
        "auth_xuid": "0",
        "clientid": "0",
        "user_type": "legacy",
        "user_properties": "{}",
        "quickPlayMultiplayer": args.quickplay,
        "quickPlayPath": "quickplay.log",
        "quickPlaySingleplayer": "",
        "quickPlayRealms": "",
        "resolution_width": "854",
        "resolution_height": "480",
    }
    features = {"has_custom_resolution": True, "is_quick_play_multiplayer": bool(args.quickplay)}
    jvm = expand_args(v["arguments"]["jvm"], subst, features)
    game = expand_args(v["arguments"]["game"], subst, features)
    if args.quickplay and "--quickPlayMultiplayer" not in game:
        game += ["--quickPlayMultiplayer", args.quickplay]  # バージョン JSON にクイックプレイの引数が無いとき

    # ログの文字コードを UTF-8 にする(既定が ASCII の環境では、日本語のメッセージが "?" になる)
    encoding = ["-Dfile.encoding=UTF-8", "-Dsun.stdout.encoding=UTF-8", "-Dstdout.encoding=UTF-8"]
    cmd = [args.java, "-Xmx1536m"] + encoding + jvm + [v["mainClass"]] + game
    if args.dry_run:
        print(" ".join(cmd))
        return 0
    os.chdir(base)  # プロセスの cwd をクライアントのディレクトリにする(試験のプロセス識別に使う)
    os.execvp(cmd[0], cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
