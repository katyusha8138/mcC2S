// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.core.handshake;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** `header` 行に続く `key = value` 形式の小さなテキスト(鍵ファイル・信頼ファイル用)。 */
final class KeyValueText {
    private final Map<String, String> values;

    private KeyValueText(Map<String, String> values) {
        this.values = values;
    }

    static KeyValueText parse(String text, String expectedHeader) throws GeneralSecurityException {
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n");
        int i = 0;
        while (i < lines.length && (lines[i].trim().isEmpty() || lines[i].trim().startsWith("#"))) {
            i++;
        }
        if (i >= lines.length || !lines[i].trim().equals(expectedHeader)) {
            throw new GeneralSecurityException("bad file header (expected " + expectedHeader + ")");
        }
        Map<String, String> map = new LinkedHashMap<>();
        for (i = i + 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                throw new GeneralSecurityException("malformed line: " + line);
            }
            String key = line.substring(0, eq).trim();
            if (map.put(key, line.substring(eq + 1).trim()) != null) {
                throw new GeneralSecurityException("duplicate key: " + key);
            }
        }
        return new KeyValueText(map);
    }

    String string(String key) throws GeneralSecurityException {
        String v = values.get(key);
        if (v == null) {
            throw new GeneralSecurityException("missing key: " + key);
        }
        return v;
    }

    String stringOr(String key, String fallback) {
        String v = values.get(key);
        return v == null ? fallback : v;
    }

    byte[] base64(String key, int expectedLen) throws GeneralSecurityException {
        try {
            byte[] b = Base64.getUrlDecoder().decode(string(key));
            if (b.length != expectedLen) {
                throw new GeneralSecurityException(key + " must be " + expectedLen + " bytes");
            }
            return b;
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException(key + " is not valid base64url");
        }
    }
}
