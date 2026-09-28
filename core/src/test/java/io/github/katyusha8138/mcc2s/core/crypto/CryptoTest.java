package io.github.katyusha8138.mcc2s.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptoTest {
    private static byte[] h(String hex) {
        return Digests.fromHex(hex);
    }

    // ---- 公開されている標準テストベクトルで、鍵の生バイト表現の出し入れが正しいことを固定する ----

    @Test
    void ed25519Rfc8032Test1() throws Exception {
        byte[] secret = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] pub = h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] expectedSig = h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        byte[] sig = Curves.sign(Curves.ed25519Private(secret), new byte[0]);
        assertArrayEquals(expectedSig, sig);
        assertTrue(Curves.verify(pub, new byte[0], sig));
        assertFalse(Curves.verify(pub, new byte[] {1}, sig));
    }

    @Test
    void x25519Rfc7748Section6_1() throws Exception {
        byte[] alicePriv = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] alicePub = h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] bobPriv = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] bobPub = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assertArrayEquals(shared, Curves.x25519(Curves.x25519Private(alicePriv), bobPub));
        assertArrayEquals(shared, Curves.x25519(Curves.x25519Private(bobPriv), alicePub));
    }

    @Test
    void x25519RejectsLowOrderPoint() throws Exception {
        KeyPair kp = Curves.generateX25519(Fixtures.RND);
        // u = 0 は位数の小さい点。共有秘密が全ゼロになるため拒否される
        assertThrows(GeneralSecurityException.class, () -> Curves.x25519(kp.getPrivate(), new byte[32]));
    }

    @Test
    void hkdfRfc5869TestCase1() {
        byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = h("000102030405060708090a0b0c");
        byte[] info = h("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = Hkdf.extract(salt, ikm);
        assertArrayEquals(h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);
        assertArrayEquals(
                h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
                Hkdf.expand(prk, info, 42));
    }

    @Test
    void hmacRfc4231Case2() {
        byte[] mac = Digests.hmac(
                "Jefe".getBytes(StandardCharsets.UTF_8), "what do ya want for nothing?".getBytes(StandardCharsets.UTF_8));
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", Digests.hex(mac));
    }

    @Test
    void sha256KnownAnswer() {
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Digests.hex(Digests.sha256("abc".getBytes(StandardCharsets.UTF_8))));
    }

    // ---- AEAD ----

    @Test
    void aeadRoundTripAndTamper() throws Exception {
        byte[] key = new byte[32];
        Fixtures.RND.nextBytes(key);
        byte[] aad = {1, 2, 3};
        byte[] ct = Aead.seal(key, 0, aad, "secret".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), Aead.open(key, 0, aad, ct));

        byte[] flipped = ct.clone();
        flipped[0] ^= 1;
        assertThrows(AEADBadTagException.class, () -> Aead.open(key, 0, aad, flipped));
        assertThrows(AEADBadTagException.class, () -> Aead.open(key, 0, new byte[] {9}, ct)); // AAD 違い
        assertThrows(AEADBadTagException.class, () -> Aead.open(key, 1, aad, ct)); // ノンス違い
        byte[] otherKey = key.clone();
        otherKey[5] ^= 1;
        assertThrows(AEADBadTagException.class, () -> Aead.open(otherKey, 0, aad, ct));
    }

    // ---- ハッシュ ----

    @Test
    void framedHashHasNoBoundaryAmbiguity() {
        byte[] a = Digests.framed("L", "a".getBytes(StandardCharsets.UTF_8), "bc".getBytes(StandardCharsets.UTF_8));
        byte[] b = Digests.framed("L", "ab".getBytes(StandardCharsets.UTF_8), "c".getBytes(StandardCharsets.UTF_8));
        assertFalse(java.util.Arrays.equals(a, b));
        byte[] c = Digests.framed("M", "a".getBytes(StandardCharsets.UTF_8), "bc".getBytes(StandardCharsets.UTF_8));
        assertFalse(java.util.Arrays.equals(a, c)); // ラベル違い
    }

    @Test
    void hexValidation() {
        assertTrue(Digests.isSha256Hex(Fixtures.sha("x")));
        assertFalse(Digests.isSha256Hex(Fixtures.sha("x").toUpperCase()));
        assertFalse(Digests.isSha256Hex("abc"));
        assertFalse(Digests.isSha256Hex(null));
        assertThrows(IllegalArgumentException.class, () -> Digests.fromHex("zz"));
        assertThrows(IllegalArgumentException.class, () -> Digests.fromHex("abc"));
    }

    @Test
    void treeHashIsOrderIndependentButContentAndNameSensitive(@TempDir Path tmp) throws IOException {
        Path a = Files.createDirectories(tmp.resolve("a"));
        Files.createDirectories(a.resolve("assets/minecraft"));
        Files.writeString(a.resolve("pack.mcmeta"), "{}");
        Files.writeString(a.resolve("assets/minecraft/x.txt"), "hello");

        Path b = Files.createDirectories(tmp.resolve("b"));
        Files.createDirectories(b.resolve("assets/minecraft"));
        Files.writeString(b.resolve("assets/minecraft/x.txt"), "hello"); // 作成順を逆に
        Files.writeString(b.resolve("pack.mcmeta"), "{}");
        assertEquals(Digests.treeHashHex(a), Digests.treeHashHex(b));

        Files.writeString(b.resolve("assets/minecraft/x.txt"), "hellO");
        assertNotEquals(Digests.treeHashHex(a), Digests.treeHashHex(b));

        Path c = Files.createDirectories(tmp.resolve("c"));
        Files.createDirectories(c.resolve("assets/minecraft"));
        Files.writeString(c.resolve("pack.mcmeta"), "{}");
        Files.writeString(c.resolve("assets/minecraft/y.txt"), "hello"); // 名前違い
        assertNotEquals(Digests.treeHashHex(a), Digests.treeHashHex(c));
    }

    @Test
    void keyCodecRoundTrip() throws Exception {
        KeyPair kp = Curves.generateEd25519(Fixtures.RND);
        byte[] rawPub = Curves.rawPublic(kp.getPublic());
        byte[] rawPriv = Curves.rawPrivate(kp.getPrivate());
        assertEquals(32, rawPub.length);
        assertEquals(32, rawPriv.length);
        byte[] sig = Curves.sign(Curves.ed25519Private(rawPriv), new byte[] {1, 2, 3});
        assertTrue(Curves.verify(rawPub, new byte[] {1, 2, 3}, sig));
        assertFalse(Curves.verify(rawPub, new byte[] {1, 2, 3}, new byte[10])); // 署名長違いは false
        assertFalse(Curves.verify(new byte[5], new byte[] {1}, sig)); // 鍵長違いも例外にせず false
    }
}
