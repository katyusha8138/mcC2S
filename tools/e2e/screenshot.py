#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
"""
仮想ディスプレイ(Xvfb)のスクリーンショットを PNG で保存する(診断用。python-xlib のみ、追加ライブラリ不要)。

  python3 screenshot.py :99 out.png
"""
import struct
import sys
import zlib

from Xlib import X, display


def write_png(path, width, height, rgb):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", zlib.compress(raw, 6)))
        f.write(chunk(b"IEND", b""))


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    d = display.Display(sys.argv[1])
    geo = d.screen().root.get_geometry()
    img = d.screen().root.get_image(0, 0, geo.width, geo.height, X.ZPixmap, 0xFFFFFFFF)
    bgrx = img.data
    rgb = bytearray(geo.width * geo.height * 3)
    rgb[0::3] = bgrx[2::4]
    rgb[1::3] = bgrx[1::4]
    rgb[2::3] = bgrx[0::4]
    write_png(sys.argv[2], geo.width, geo.height, bytes(rgb))
    d.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
