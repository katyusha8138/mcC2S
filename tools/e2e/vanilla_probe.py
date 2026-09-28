#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 mcC2S contributors
"""
mcC2S 導入サーバーに「mcC2S を持たないクライアント」として接続し、拒否されることを確認するプローブ。

Minecraft 1.21.1 (プロトコル 767) のログイン〜設定フェーズだけを話す最小クライアント。
オフラインモードのテストサーバー用(認証・暗号化は行わない)。

  python3 vanilla_probe.py [--host 127.0.0.1] [--port 25599] [--name Probe]

終了コード: 0 = mcC2S に拒否された(期待どおり) / 1 = 拒否されず参加できた / 2 = 想定外の失敗
"""
import argparse
import re
import socket
import struct
import sys
import time
import uuid
import zlib


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def mc_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return varint(len(b)) + b


class Conn:
    def __init__(self, host, port, timeout):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.compress = -1

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("connection closed")
            buf += chunk
        return buf

    def _read_varint(self):
        result = shift = 0
        while True:
            b = self._read_exact(1)[0]
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7

    def send(self, packet_id: int, payload: bytes = b""):
        body = varint(packet_id) + payload
        if self.compress >= 0:
            body = varint(0) + body  # 閾値以下は無圧縮(dataLength=0)。閾値超は送らない想定
        self.sock.sendall(varint(len(body)) + body)

    def recv(self):
        length = self._read_varint()
        data = self._read_exact(length)
        if self.compress >= 0:
            # dataLength を読む
            i, shift, data_len = 0, 0, 0
            while True:
                b = data[i]
                data_len |= (b & 0x7F) << shift
                i += 1
                if not b & 0x80:
                    break
                shift += 7
            data = zlib.decompress(data[i:]) if data_len else data[i:]
        i, shift, pid = 0, 0, 0
        while True:
            b = data[i]
            pid |= (b & 0x7F) << shift
            i += 1
            if not b & 0x80:
                break
            shift += 7
        return pid, data[i:]


def extract_text(raw: bytes) -> str:
    """Disconnect の理由(NBT のテキストコンポーネント)から、読める文字列を取り出す。"""
    texts = re.findall(rb"[\x20-\x7e\xc2-\xf4][\x20-\x7e\x80-\xbf\xc2-\xf4]{6,}", raw)
    return " | ".join(t.decode("utf-8", "replace") for t in texts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=25599)
    ap.add_argument("--name", default="Probe")
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    c = Conn(args.host, args.port, args.timeout)
    # Handshake -> login
    c.send(0x00, varint(767) + mc_string(args.host) + struct.pack(">H", args.port) + varint(2))
    c.send(0x00, mc_string(args.name) + uuid.uuid3(uuid.NAMESPACE_DNS, "OfflinePlayer:" + args.name).bytes)

    state = "login"
    deadline = time.time() + args.timeout
    started = time.time()
    packets = 0
    while time.time() < deadline:
        try:
            pid, payload = c.recv()
        except (EOFError, ConnectionResetError, socket.timeout) as e:
            print(f"[probe] connection ended: {e} after {time.time() - started:.1f}s (state={state})")
            return 2
        packets += 1
        if state == "login":
            if pid == 0x03:  # Set Compression
                c.compress = int.from_bytes(payload[:1], "big") if payload[0] < 0x80 else 256
                # 閾値を varint として読む
                v, shift, i = 0, 0, 0
                while True:
                    b = payload[i]
                    v |= (b & 0x7F) << shift
                    i += 1
                    if not b & 0x80:
                        break
                    shift += 7
                c.compress = v
            elif pid == 0x02:  # Login Success
                c.send(0x03)  # Login Acknowledged
                state = "config"
                print(f"[probe] logged in as {args.name}; entering configuration phase")
            elif pid == 0x00:  # Disconnect (login)
                print("[probe] disconnected during login:", extract_text(payload))
                return 2
            continue

        # configuration phase
        if pid == 0x02:  # Disconnect
            reason = extract_text(payload)
            print(f"[probe] DISCONNECTED after {time.time() - started:.1f}s: {reason}")
            return 0 if "mcC2S" in reason else 2
        elif pid == 0x03:  # Finish Configuration -> ここまで来たら参加できてしまった
            print("[probe] server sent Finish Configuration: the client was ADMITTED")
            return 1
        elif pid == 0x04:  # Keep Alive
            c.send(0x04, payload[:8])
        elif pid == 0x05:  # Ping
            c.send(0x05, payload[:4])
        elif pid == 0x0E:  # Known Packs -> 空で返す
            c.send(0x07, varint(0))
        # それ以外(brand / registry data / tags 等)は読み捨てる

    print(f"[probe] timed out after {args.timeout}s without a decision (packets={packets})")
    return 2


if __name__ == "__main__":
    sys.exit(main())
