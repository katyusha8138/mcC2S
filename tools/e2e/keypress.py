#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
"""
仮想ディスプレイ(Xvfb)にキー入力を送る(XTEST)。e2e.sh の onchange シナリオが、
Minecraft の F3+T(リソースの再読み込み)を押すために使う。python-xlib が必要。

  python3 keypress.py :99 F3+t
"""
import sys
import time

from Xlib import X, XK, display
from Xlib.ext import xtest


def find_window(d, name_prefix):
    """ルートの子孫から、名前が name_prefix で始まるウィンドウを探す。"""
    stack = list(d.screen().root.query_tree().children)
    while stack:
        w = stack.pop()
        try:
            name = w.get_wm_name()
        except Exception:  # noqa: BLE001 (消えたウィンドウなど)
            name = None
        if name and name.startswith(name_prefix):
            return w
        try:
            stack.extend(w.query_tree().children)
        except Exception:  # noqa: BLE001
            pass
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    d = display.Display(sys.argv[1])
    codes = []
    for name in sys.argv[2].split("+"):
        keysym = XK.string_to_keysym(name)
        if keysym == 0:
            print(f"unknown key: {name}")
            return 2
        codes.append(d.keysym_to_keycode(keysym))

    # ウィンドウマネージャが無いため、Minecraft のウィンドウに入力フォーカスを明示的に与える。
    # (フォーカスが無いと「フォーカス喪失で一時停止」になり、キーがゲームに届かない)
    win = find_window(d, "Minecraft")
    if win is not None:
        geo = win.get_geometry()
        win.set_input_focus(X.RevertToParent, X.CurrentTime)
        x, y = geo.x + geo.width // 2, geo.y + geo.height // 2
        print(f"[keypress] focused window {win.id:#x} ({geo.width}x{geo.height} at {geo.x},{geo.y})")
    else:
        x, y = 400, 240
        print("[keypress] Minecraft window not found; sending keys to the pointer position")
    xtest.fake_input(d, X.MotionNotify, x=x, y=y)
    d.sync()
    time.sleep(0.3)
    for c in codes:
        xtest.fake_input(d, X.KeyPress, c)
        d.sync()
        time.sleep(0.15)
    time.sleep(0.15)
    for c in reversed(codes):
        xtest.fake_input(d, X.KeyRelease, c)
        d.sync()
        time.sleep(0.1)
    d.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
