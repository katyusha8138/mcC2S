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

    # ウィンドウマネージャが無いので、ポインタの下のウィンドウにキーが届く。画面の中央付近に置く。
    xtest.fake_input(d, X.MotionNotify, x=400, y=240)
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
