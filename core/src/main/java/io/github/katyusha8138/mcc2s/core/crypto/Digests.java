package io.github.katyusha8138.mcc2s.core.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** SHA-256 / HMAC-SHA256 と 16 進変換のユーティリティ。JDK 標準 JCA のみ使用。 */
public final class Digests {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Digests() {}

    public static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static byte[] sha256(byte[] data) {
        return sha256().digest(data);
    }

    public static byte[] sha256(InputStream in) throws IOException {
        MessageDigest md = sha256();
        byte[] buf = new byte[64 * 1024];
        int n;
        while ((n = in.read(buf)) > 0) {
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    public static byte[] sha256(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return sha256(in);
        }
    }

    /** ドメイン分離ラベルと、各要素を 4 バイト長で区切った曖昧さのない SHA-256。 */
    public static byte[] framed(String label, byte[]... parts) {
        MessageDigest md = sha256();
        updateFramed(md, label.getBytes(StandardCharsets.UTF_8));
        for (byte[] p : parts) {
            updateFramed(md, p);
        }
        return md.digest();
    }

    private static void updateFramed(MessageDigest md, byte[] p) {
        md.update((byte) (p.length >>> 24));
        md.update((byte) (p.length >>> 16));
        md.update((byte) (p.length >>> 8));
        md.update((byte) p.length);
        md.update(p);
    }

    public static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            Mac mac = newMac(key);
            for (byte[] p : parts) {
                mac.update(p);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public static Mac newMac(byte[] key) throws GeneralSecurityException {
        if (key.length == 0) {
            throw new IllegalArgumentException("empty HMAC key");
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac;
    }

    /** 定数時間比較。 */
    public static boolean equal(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    public static String hex(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            out[i * 2] = HEX[(b[i] >>> 4) & 0xF];
            out[i * 2 + 1] = HEX[b[i] & 0xF];
        }
        return new String(out);
    }

    public static byte[] fromHex(String s) {
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** 小文字 16 進 64 文字か。 */
    public static boolean isSha256Hex(String s) {
        if (s == null || s.length() != 64) {
            return false;
        }
        for (int i = 0; i < 64; i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /**
     * フォルダ形式リソースパック用のツリーハッシュ。
     * 相対パス(`/` 区切り)でソートし、(パス長, パス, ファイルの SHA-256) を連結して SHA-256 を取る。
     * シンボリックリンクは辿る(リンク先に中身を隠されないため。循環は例外になる)。
     */
    public static String treeHashHex(Path dir) throws IOException {
        List<Path> files;
        try (Stream<Path> s = Files.walk(dir, FileVisitOption.FOLLOW_LINKS)) {
            files = s.filter(Files::isRegularFile).collect(Collectors.toCollection(ArrayList::new));
        }
        List<String> rels = new ArrayList<>();
        for (Path f : files) {
            StringBuilder sb = new StringBuilder();
            for (Path part : dir.relativize(f)) {
                if (sb.length() > 0) {
                    sb.append('/');
                }
                sb.append(part.toString());
            }
            rels.add(sb.toString());
        }
        Collections.sort(rels);
        MessageDigest md = sha256();
        for (String rel : rels) {
            byte[] p = rel.getBytes(StandardCharsets.UTF_8);
            md.update((byte) (p.length >>> 24));
            md.update((byte) (p.length >>> 16));
            md.update((byte) (p.length >>> 8));
            md.update((byte) p.length);
            md.update(p);
            md.update(sha256(dir.resolve(rel)));
        }
        return hex(md.digest());
    }
}
