// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.cli;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** `--flag value` / `--switch` / 位置引数だけの最小の引数パーサー。未知のフラグはエラーにする。 */
final class Args {
    final Map<String, String> values = new HashMap<>();
    final Set<String> switches = new java.util.HashSet<>();
    final List<String> positional = new ArrayList<>();

    static Args parse(List<String> args, Set<String> valueFlags, Set<String> switchFlags) {
        Args a = new Args();
        for (int i = 0; i < args.size(); i++) {
            String s = args.get(i);
            if (s.equals("--")) {
                a.positional.addAll(args.subList(i + 1, args.size()));
                break;
            }
            if (s.startsWith("--")) {
                String name = s.substring(2);
                if (valueFlags.contains(name)) {
                    if (i + 1 >= args.size()) {
                        throw new UsageException("--" + name + " requires a value");
                    }
                    a.values.put(name, args.get(++i));
                } else if (switchFlags.contains(name)) {
                    a.switches.add(name);
                } else {
                    throw new UsageException("unknown option: " + s);
                }
            } else {
                a.positional.add(s);
            }
        }
        return a;
    }

    String require(String name) {
        String v = values.get(name);
        if (v == null) {
            throw new UsageException("--" + name + " is required");
        }
        return v;
    }

    String get(String name, String fallback) {
        return values.getOrDefault(name, fallback);
    }

    boolean has(String name) {
        return switches.contains(name);
    }

    static final class UsageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }
}
