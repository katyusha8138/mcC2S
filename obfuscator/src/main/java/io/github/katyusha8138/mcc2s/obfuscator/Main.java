// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.obfuscator;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code obfuscator <入力.jar> <出力.jar> [パッケージ...]}
 * <p>指定パッケージ(例 {@code io.github.katyusha8138.mcc2s.core})以下のクラスの文字列定数を難読化する。
 * パッケージを省略するとすべてのクラスが対象。
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("usage: obfuscator <in.jar> <out.jar> [package...]");
            System.exit(2);
        }
        List<String> prefixes = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            prefixes.add(args[i].replace('.', '/') + "/");
        }
        int n = new StringObfuscator(prefixes).transformJar(Path.of(args[0]), Path.of(args[1]));
        System.out.println("obfuscated " + n + " string constant(s) -> " + args[1]);
    }
}
