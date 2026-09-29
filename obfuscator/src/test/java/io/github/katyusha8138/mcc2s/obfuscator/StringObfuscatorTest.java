// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.obfuscator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StringObfuscatorTest {
    private static final String SUBJECT = "io.github.katyusha8138.mcc2s.obfuscator.SampleSubject";

    /** SampleSubject とその内部クラス(SampleSubject$...)を、変換したバイト列から読み込む。 */
    private static final class TransformingLoader extends ClassLoader {
        private final StringObfuscator obfuscator;
        final Map<String, byte[]> defined = new HashMap<>();
        int replaced;

        TransformingLoader(StringObfuscator obfuscator) {
            super(ClassLoader.getPlatformClassLoader());
            this.obfuscator = obfuscator;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (!name.startsWith(SUBJECT)) {
                throw new ClassNotFoundException(name);
            }
            byte[] original = bytesOf(name);
            StringObfuscator.Result r = obfuscator.transform(original);
            replaced += r.strings();
            defined.put(name, r.bytes());
            return defineClass(name, r.bytes(), 0, r.bytes().length);
        }
    }

    private static byte[] bytesOf(String className) {
        String path = className.replace('.', '/') + ".class";
        try (InputStream is = StringObfuscatorTest.class.getClassLoader().getResourceAsStream(path)) {
            if (is == null) {
                throw new IllegalStateException("no such class file: " + path);
            }
            return is.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static String run(ClassLoader loader) throws Exception {
        Class<?> c = Class.forName(SUBJECT, true, loader);
        return ((Supplier<String>) c.getDeclaredConstructor().newInstance()).get();
    }

    private static boolean contains(byte[] haystack, String needle) {
        byte[] n = needle.getBytes(StandardCharsets.UTF_8);
        outer:
        for (int i = 0; i + n.length <= haystack.length; i++) {
            for (int j = 0; j < n.length; j++) {
                if (haystack[i + j] != n[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    @Test
    void behaviourIsUnchanged() throws Exception {
        String before = run(SampleSubject.class.getClassLoader());
        TransformingLoader loader = new TransformingLoader(new StringObfuscator(List.of()));
        String after = run(loader);

        assertEquals(before, after);
        assertTrue(loader.replaced > 15, "many constants should have been replaced: " + loader.replaced);
        assertTrue(before.contains("日本語のメッセージ/✓/😀-SUBJECT-UNICODE"));
    }

    @Test
    void plaintextLiteralsDisappearFromTheClassFiles() throws Exception {
        TransformingLoader loader = new TransformingLoader(new StringObfuscator(List.of()));
        run(loader);

        // ldc だけで使われている文字列(定数フィールド・invokedynamic の定型文・アノテーションは対象外)
        String[] hidden = {
            "SUBJECT-PLAIN-LITERAL", "SUBJECT-STATIC-INIT-", "SUBJECT-SWITCH-ONE", "SUBJECT-SWITCH-TWO",
            "SUBJECT-LAMBDA-BODY", "SUBJECT-GREETER-NAME", "SUBJECT-DEFAULT-METHOD-", "SUBJECT-ENUM-ALPHA",
            "SUBJECT-ENUM-BETA", "SUBJECT-RECORD-SEP", "SUBJECT-PAIR-LEFT", "SUBJECT-ANONYMOUS",
            "SUBJECT-CONSTRUCTOR-DEFAULT", "日本語のメッセージ",
        };
        for (String s : hidden) {
            boolean originalHas = false;
            boolean transformedHas = false;
            for (Map.Entry<String, byte[]> e : loader.defined.entrySet()) {
                originalHas |= contains(bytesOf(e.getKey()), s);
                transformedHas |= contains(e.getValue(), s);
            }
            assertTrue(originalHas, "the literal should be in the original classes: " + s);
            assertFalse(transformedHas, "the literal must not remain in plain text: " + s);
        }
    }

    @Test
    void outputIsDeterministic() {
        byte[] original = bytesOf(SUBJECT);
        byte[] first = new StringObfuscator(List.of()).transform(original).bytes();
        byte[] second = new StringObfuscator(List.of()).transform(original).bytes();
        assertArrayEquals(first, second);
        assertNotEquals(original.length, first.length);
    }

    @Test
    void doesNotTransformTwice() {
        StringObfuscator obfuscator = new StringObfuscator(List.of());
        byte[] once = obfuscator.transform(bytesOf(SUBJECT)).bytes();
        StringObfuscator.Result again = obfuscator.transform(once);
        assertEquals(0, again.strings());
        assertArrayEquals(once, again.bytes());
    }

    @Test
    void onlySelectedPackagesAreTransformed() {
        byte[] original = bytesOf(SUBJECT);
        StringObfuscator.Result r = new StringObfuscator(List.of("some/other/pkg/")).transform(original);
        assertEquals(0, r.strings());
        assertArrayEquals(original, r.bytes());

        StringObfuscator mine = new StringObfuscator(List.of("io/github/katyusha8138/mcc2s/obfuscator/"));
        assertTrue(mine.transform(original).strings() > 0);
    }

    @Test
    void encryptionSkipsUnrepresentableStrings() {
        assertTrue(StringObfuscator.encryptable("abc"));
        assertFalse(StringObfuscator.encryptable(""));
        assertFalse(StringObfuscator.encryptable("lone-surrogate-\uD800"));
        assertFalse(StringObfuscator.encryptable("x".repeat(30_001)));
        assertTrue(StringObfuscator.encryptable("x".repeat(30_000)));

        String cipher = StringObfuscator.encrypt("hello", 1234567L);
        assertNotEquals("hello", cipher);
        assertEquals(5, cipher.length());
    }

    @Test
    void jarIsTransformedEntryByEntryAndKeepsOtherFiles(@TempDir Path dir) throws Exception {
        Path in = dir.resolve("in.jar");
        Path out = dir.resolve("out.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(in))) {
            for (String n : List.of(SUBJECT, SUBJECT + "$Pair", SUBJECT + "$Kind")) {
                jos.putNextEntry(new JarEntry(n.replace('.', '/') + ".class"));
                jos.write(bytesOf(n));
                jos.closeEntry();
            }
            jos.putNextEntry(new JarEntry("data/notes.txt"));
            jos.write("keep me SUBJECT-PLAIN-LITERAL".getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }

        int n = new StringObfuscator(List.of()).transformJar(in, out);
        assertTrue(n > 0);
        Path out2 = dir.resolve("out2.jar");
        new StringObfuscator(List.of()).transformJar(in, out2);
        assertArrayEquals(Files.readAllBytes(out), Files.readAllBytes(out2), "the jar must be byte-for-byte reproducible");

        try (JarFile jar = new JarFile(out.toFile())) {
            byte[] notes = jar.getInputStream(jar.getEntry("data/notes.txt")).readAllBytes();
            assertEquals("keep me SUBJECT-PLAIN-LITERAL", new String(notes, StandardCharsets.UTF_8));
            byte[] subject = jar.getInputStream(jar.getEntry(SUBJECT.replace('.', '/') + ".class")).readAllBytes();
            assertFalse(contains(subject, "SUBJECT-PLAIN-LITERAL"));
        }
    }
}
