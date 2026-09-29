// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.obfuscator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * クラスファイル中の文字列定数({@code ldc "..."})を、実行時に元へ戻す呼び出しに置き換える。
 *
 * <p>目的は「クラスファイルを眺めるだけでは、メッセージ・ラベル・ファイル名などの文字列から動作を推測できない」
 * ようにする手間の増加であり、秘匿ではない(復号処理は各クラスに入っていて、鍵も呼び出し側にある)。
 * 出力は入力と対象だけで決まる(乱数・時刻を使わない)ので、ビルドは再現できる。
 *
 * <p>{@code static final String} の定数フィールド(ConstantValue 属性)は、属性を外してクラスの静的初期化子
 * ({@code <clinit>})の先頭で代入する形に変える(初期化の順序は変わらない)。
 *
 * <p>対象外(平文のまま残る):
 * <ul>
 *   <li>文字列連結({@code invokedynamic})の定型文。バイトコード上は {@code ldc} ではなくブートストラップ引数のため。
 *       core / common は {@code -XDstringConcat=inline} でコンパイルして、この形を作らないようにしている</li>
 *   <li>アノテーションの値</li>
 *   <li>空文字列と、UTF-8 で往復できない文字列(対になっていないサロゲート)、極端に長い文字列</li>
 * </ul>
 */
public final class StringObfuscator {
    /** 復号メソッド名。後段の ProGuard が名前を付け替える。 */
    static final String DECODE_NAME = "$mcc2s$d";

    static final String DECODE_DESC = "(Ljava/lang/String;J)Ljava/lang/String;";

    /** 定数プールの UTF-8 は 65,535 バイトまで。暗号文の各文字は最大 2 バイトになるので余裕を見る。 */
    private static final int MAX_PLAIN_UTF8_BYTES = 30_000;

    private static final long GOLDEN = 0x9E3779B97F4A7C15L;

    private final List<String> prefixes;

    /** @param prefixes 対象クラスの内部名の接頭辞(例 {@code io/github/katyusha8138/mcc2s/core/})。空なら全クラス。 */
    public StringObfuscator(List<String> prefixes) {
        this.prefixes = List.copyOf(prefixes);
    }

    /** 1 クラスの変換結果。 */
    public record Result(byte[] bytes, int strings) {}

    /** クラスファイルを変換する。文字列を置き換えなかったときは入力をそのまま返す(strings = 0)。 */
    public Result transform(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        if (!selected(reader.getClassName()) || alreadyProcessed(reader)) {
            return new Result(classBytes, 0);
        }
        // 呼び出しでスタックが深くなるので、最大スタックを再計算する(分岐は増えないのでフレームは変わらない)
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        Encryptor encryptor = new Encryptor(writer);
        reader.accept(encryptor, 0);
        if (encryptor.replaced == 0) {
            return new Result(classBytes, 0);
        }
        return new Result(writer.toByteArray(), encryptor.replaced);
    }

    /** jar を読み、対象クラスの文字列を難読化した jar を書く。エントリの順序と内容(クラス以外)は保つ。 */
    public int transformJar(Path in, Path out) throws IOException {
        int total = 0;
        // ZIP の時刻は Gradle の再現可能アーカイブと同じ固定値にする(タイムゾーンに依存しない)
        LocalDateTime fixed = LocalDateTime.of(1980, 2, 1, 0, 0, 0);
        try (JarFile jar = new JarFile(in.toFile());
                OutputStream os = Files.newOutputStream(out);
                JarOutputStream jos = new JarOutputStream(os)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry e = entries.nextElement();
                byte[] data = e.isDirectory() ? new byte[0] : read(jar, e);
                if (e.getName().endsWith(".class") && !e.getName().equals("module-info.class")) {
                    Result r = transform(data);
                    data = r.bytes();
                    total += r.strings();
                }
                ZipEntry n = new ZipEntry(e.getName());
                n.setTimeLocal(fixed);
                jos.putNextEntry(n);
                jos.write(data);
                jos.closeEntry();
            }
        }
        return total;
    }

    private static byte[] read(JarFile jar, JarEntry e) throws IOException {
        try (InputStream is = jar.getInputStream(e)) {
            return is.readAllBytes();
        }
    }

    private boolean selected(String internalName) {
        if (prefixes.isEmpty()) {
            return true;
        }
        for (String p : prefixes) {
            if (internalName.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    /** 二重に変換しない(復号メソッドがあるクラスは変換済み)。 */
    private static boolean alreadyProcessed(ClassReader reader) {
        ClassNode node = new ClassNode();
        reader.accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        for (MethodNode m : node.methods) {
            if (m.name.equals(DECODE_NAME)) {
                return true;
            }
        }
        return false;
    }

    // ---- 文字列の変換 ----

    private static long seedOf(String className) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(className.getBytes(StandardCharsets.UTF_8));
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (h[i] & 0xFF);
            }
            return v;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 はすべての JDK にある
        }
    }

    private static long splitmix64(long z) {
        z += GOLDEN;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    /** 暗号文: UTF-8 のバイト列に xorshift64 の鍵ストリームを XOR し、各バイトを 1 文字(0〜255)にしたもの。 */
    static String encrypt(String plain, long key) {
        byte[] bytes = plain.getBytes(StandardCharsets.UTF_8);
        char[] out = new char[bytes.length];
        long x = key;
        for (int i = 0; i < bytes.length; i++) {
            x ^= x << 13;
            x ^= x >>> 7;
            x ^= x << 17;
            out[i] = (char) ((bytes[i] ^ (int) x) & 0xFF);
        }
        return new String(out);
    }

    static boolean encryptable(String s) {
        if (s.isEmpty()) {
            return false;
        }
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        // 対になっていないサロゲートは UTF-8 で往復できない(元の文字列に戻せない)ので対象外
        return bytes.length <= MAX_PLAIN_UTF8_BYTES && new String(bytes, StandardCharsets.UTF_8).equals(s);
    }

    /** 定数フィールドの初期化({@code <clinit>} の先頭に入れる)。 */
    private record FieldInit(String name, String descriptor, String cipher, long key) {}

    private final class Encryptor extends ClassVisitor {
        private String owner;
        private boolean isInterface;
        private int version;
        private long seed;
        private int counter;
        private boolean sawClinit;
        private final List<FieldInit> fieldInits = new ArrayList<>();
        int replaced;

        Encryptor(ClassVisitor next) {
            super(Opcodes.ASM9, next);
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.owner = name;
            this.isInterface = (access & Opcodes.ACC_INTERFACE) != 0;
            this.version = version & 0xFFFF;
            this.seed = seedOf(name);
            super.visit(version, access, name, signature, superName, interfaces);
        }

        private long nextKey() {
            long key = splitmix64(seed + (++counter) * GOLDEN);
            return key == 0 ? GOLDEN : key; // xorshift は 0 を鍵にできない
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
            if (version >= Opcodes.V9
                    && (access & Opcodes.ACC_STATIC) != 0
                    && descriptor.equals("Ljava/lang/String;")
                    && value instanceof String s
                    && encryptable(s)) {
                long key = nextKey();
                fieldInits.add(new FieldInit(name, descriptor, encrypt(s, key), key));
                replaced++;
                return super.visitField(access, name, descriptor, signature, null); // 定数値を外す(<clinit> で代入する)
            }
            return super.visitField(access, name, descriptor, signature, value);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null || version < Opcodes.V9) {
                return mv; // private な static メソッドをインターフェースに置けるのは Java 9 以降
            }
            boolean clinit = name.equals("<clinit>");
            sawClinit |= clinit;
            return new MethodVisitor(Opcodes.ASM9, mv) {
                @Override
                public void visitCode() {
                    super.visitCode();
                    if (clinit) {
                        emitFieldInits(mv); // 定数フィールドは、他の静的初期化より先に値が入っていた。その順序を保つ
                    }
                }

                @Override
                public void visitLdcInsn(Object value) {
                    if (value instanceof String s && encryptable(s)) {
                        long key = nextKey();
                        super.visitLdcInsn(encrypt(s, key));
                        super.visitLdcInsn(key);
                        super.visitMethodInsn(Opcodes.INVOKESTATIC, owner, DECODE_NAME, DECODE_DESC, isInterface);
                        replaced++;
                    } else {
                        super.visitLdcInsn(value);
                    }
                }
            };
        }

        private void emitFieldInits(MethodVisitor out) {
            for (FieldInit f : fieldInits) {
                out.visitLdcInsn(f.cipher());
                out.visitLdcInsn(f.key());
                out.visitMethodInsn(Opcodes.INVOKESTATIC, owner, DECODE_NAME, DECODE_DESC, isInterface);
                out.visitFieldInsn(Opcodes.PUTSTATIC, owner, f.name(), f.descriptor());
            }
        }

        @Override
        public void visitEnd() {
            if (!fieldInits.isEmpty() && !sawClinit) {
                MethodVisitor mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                mv.visitCode();
                emitFieldInits(mv);
                mv.visitInsn(Opcodes.RETURN);
                mv.visitMaxs(0, 0);
                mv.visitEnd();
            }
            if (replaced > 0) {
                copyDecoder();
            }
            super.visitEnd();
        }

        /** 雛形 {@link Decoder#decode} のバイトコードを、このクラスの private static synthetic メソッドとして追加する。 */
        private void copyDecoder() {
            ClassNode template = new ClassNode();
            try (InputStream is = Decoder.class.getResourceAsStream("Decoder.class")) {
                if (is == null) {
                    throw new IllegalStateException("Decoder.class not found");
                }
                new ClassReader(is).accept(template, 0);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            for (MethodNode m : template.methods) {
                if (m.name.equals("decode")) {
                    m.access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
                    m.name = DECODE_NAME;
                    m.localVariables = null; // デバッグ情報は持ち込まない
                    m.accept(cv);
                    return;
                }
            }
            throw new IllegalStateException("Decoder.decode not found");
        }
    }

}
