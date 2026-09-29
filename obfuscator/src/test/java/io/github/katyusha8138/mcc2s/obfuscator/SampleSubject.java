// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.obfuscator;

import java.util.function.Supplier;

/** 難読化の前後で結果が変わらないことを確かめるための被験クラス。いろいろな形の文字列定数を使う。 */
public final class SampleSubject implements Supplier<String> {
    /** ConstantValue 属性のフィールド(定義側は平文のまま残る。使用側の ldc は置き換わる)。 */
    static final String CONSTANT = "SUBJECT-CONSTANT-FIELD";

    static final String STATIC_INIT;

    static {
        STATIC_INIT = "SUBJECT-STATIC-INIT-".concat("tail");
    }

    interface Greeter {
        String name();

        default String greet() {
            return "SUBJECT-DEFAULT-METHOD-".concat(name());
        }
    }

    enum Kind {
        ALPHA("SUBJECT-ENUM-ALPHA"),
        BETA("SUBJECT-ENUM-BETA");

        final String label;

        Kind(String label) {
            this.label = label;
        }
    }

    record Pair(String left, String right) {
        String joined() {
            return left.concat("SUBJECT-RECORD-SEP").concat(right);
        }
    }

    private final String prefix;

    public SampleSubject() {
        this("SUBJECT-CONSTRUCTOR-DEFAULT"); // this(...) の引数に ldc がある
    }

    private SampleSubject(String prefix) {
        this.prefix = prefix;
    }

    private static String pick(String key) {
        switch (key) {
            case "SUBJECT-SWITCH-ONE":
                return "first";
            case "SUBJECT-SWITCH-TWO":
                return "second";
            default:
                return "other";
        }
    }

    @Override
    public String get() {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix).append('|');
        sb.append(CONSTANT).append('|');
        sb.append(STATIC_INIT).append('|');
        sb.append("SUBJECT-PLAIN-LITERAL").append('|');
        sb.append("").append("|"); // 空文字列は対象外
        sb.append("日本語のメッセージ/✓/😀-SUBJECT-UNICODE").append('|');
        sb.append("tab\tnewline\nnul\u0000quote\"backslash\\").append('|');
        sb.append(pick("SUBJECT-SWITCH-TWO")).append(pick("no-match")).append('|');
        Supplier<String> lambda = () -> "SUBJECT-LAMBDA-BODY";
        sb.append(lambda.get()).append('|');
        Greeter g = () -> "SUBJECT-GREETER-NAME";
        sb.append(g.greet()).append('|');
        for (Kind k : Kind.values()) {
            sb.append(k.label).append(':').append(k.name()).append(',');
        }
        sb.append(new Pair("SUBJECT-PAIR-LEFT", "right").joined()).append('|');
        sb.append(new Object() {
            @Override
            public String toString() {
                return "SUBJECT-ANONYMOUS";
            }
        });
        return sb.toString();
    }
}
