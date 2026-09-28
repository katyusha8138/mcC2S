package io.github.katyusha8138.mcc2s.core.model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import io.github.katyusha8138.mcc2s.core.wire.WireException;
import io.github.katyusha8138.mcc2s.core.wire.WireWriter;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import org.junit.jupiter.api.Test;

class ManifestTest {
    private static Entry e(EntryKind k, String id) {
        return new Entry(k, id, "1.0", Fixtures.sha(id));
    }

    @Test
    void roundTripPreservesEverythingIncludingProofs() {
        byte[] proof = new byte[32];
        Fixtures.RND.nextBytes(proof);
        Manifest m = Fixtures.manifest(
                EnumSet.of(Scope.MODS, Scope.RESOURCE_PACKS),
                e(EntryKind.MOD, "jei"),
                e(EntryKind.LIBRARY, "hidden.jar"),
                new Entry(EntryKind.RESOURCE_PACK, "file/日本語パック.zip", "", Fixtures.sha("rp"), proof));
        Manifest back = Manifest.decode(m.encode());
        assertEquals(m, back);
        assertArrayEquals(proof, back.entries().get(2).proof());
    }

    @Test
    void entryValidation() {
        assertThrows(IllegalArgumentException.class, () -> new Entry(EntryKind.MOD, "a\nb", "1", Fixtures.sha("x")));
        assertThrows(IllegalArgumentException.class, () -> new Entry(EntryKind.MOD, "a\u001b[31m", "1", Fixtures.sha("x")));
        assertThrows(IllegalArgumentException.class, () -> new Entry(EntryKind.MOD, "a", "1", "NOTHEX"));
        assertThrows(IllegalArgumentException.class, () -> new Entry(EntryKind.MOD, "a", "1", Fixtures.sha("x"), new byte[5]));
        assertThrows(IllegalArgumentException.class, () -> new Entry(EntryKind.MOD, "x".repeat(257), "1", Fixtures.sha("x")));
    }

    @Test
    void decodeRejectsMalformedInputs() {
        Manifest m = Fixtures.manifest(EnumSet.of(Scope.MODS), e(EntryKind.MOD, "a"));
        byte[] good = m.encode();

        assertThrows(WireException.class, () -> Manifest.decode(new byte[0]));
        byte[] trailing = java.util.Arrays.copyOf(good, good.length + 1);
        assertThrows(WireException.class, () -> Manifest.decode(trailing));
        assertThrows(WireException.class, () -> Manifest.decode(java.util.Arrays.copyOf(good, good.length - 1)));
        byte[] badVersion = good.clone();
        badVersion[0] = 9;
        assertThrows(WireException.class, () -> Manifest.decode(badVersion));
    }

    @Test
    void decodeRejectsUnknownScopeBitsKindsAndProofFlags() {
        // 既知項目 0 件のマニフェストを手組みして各フィールドを不正にする
        byte[] unknownScope = header(0xF0).u16(0).toByteArray();
        assertThrows(WireException.class, () -> Manifest.decode(unknownScope));

        byte[] unknownKind = header(1).u16(1).u8(99).str("a", 10).str("1", 10).fixed(new byte[32], 32).u8(0).toByteArray();
        assertThrows(WireException.class, () -> Manifest.decode(unknownKind));

        byte[] badProofFlag = header(1).u16(1).u8(1).str("a", 10).str("1", 10).fixed(new byte[32], 32).u8(2).toByteArray();
        assertThrows(WireException.class, () -> Manifest.decode(badProofFlag));

        byte[] controlChars = header(1).u16(1).u8(1).str("a\nb", 10).str("1", 10).fixed(new byte[32], 32).u8(0).toByteArray();
        assertThrows(WireException.class, () -> Manifest.decode(controlChars));
    }

    @Test
    void decodeRejectsOversizedEntryCount() {
        byte[] huge = header(1).u16(65535).toByteArray();
        assertThrows(WireException.class, () -> Manifest.decode(huge));
    }

    @Test
    void constructorEnforcesEntryLimit() {
        List<Entry> many = new ArrayList<>();
        for (int i = 0; i <= Manifest.MAX_ENTRIES; i++) {
            many.add(e(EntryKind.MOD, "m" + i));
        }
        assertThrows(IllegalArgumentException.class, () -> Fixtures.manifest(EnumSet.of(Scope.MODS), many));
    }

    private static WireWriter header(int scopeMask) {
        return new WireWriter()
                .u8(Manifest.FORMAT_VERSION)
                .str("1.21.1", 100)
                .str("neoforge", 100)
                .str("21.1.0", 100)
                .str("0.1.0", 100)
                .u8(scopeMask);
    }
}
