package io.github.katyusha8138.mcc2s.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.katyusha8138.mcc2s.core.handshake.ServerVerdict;
import io.github.katyusha8138.mcc2s.core.model.EntryKind;
import io.github.katyusha8138.mcc2s.core.testsupport.Fixtures;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ViolationReportTest {
    private static ViolationReport report(String player, String modId) {
        return new ViolationReport(
                Instant.parse("2026-09-28T12:00:00Z"),
                player,
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                "203.0.113.5:25565",
                new byte[] {0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, (byte) 0x8b},
                ServerVerdict.Status.DENIED,
                List.of(new Violation(ViolationCode.NOT_ALLOWED, EntryKind.MOD, modId, "1.0", Fixtures.sha("x"), "not in allow list")));
    }

    @Test
    void refCodeIsStableUppercaseHex() {
        assertEquals("MC2S-1A2B3C4D5E6F7A8B", report("Steve", "wurst").refCode());
    }

    @Test
    void jsonLineIsValidJsonAndCarriesAllFields() {
        JsonObject o = JsonParser.parseString(report("Steve", "wurst").toJsonLine()).getAsJsonObject();
        assertEquals("MC2S-1A2B3C4D5E6F7A8B", o.get("ref").getAsString());
        assertEquals("DENIED", o.get("action").getAsString());
        assertEquals("Steve", o.get("player").getAsString());
        JsonArray v = o.getAsJsonArray("violations");
        assertEquals(1, v.size());
        assertEquals("NOT_ALLOWED", v.get(0).getAsJsonObject().get("code").getAsString());
        assertEquals("MOD", v.get(0).getAsJsonObject().get("kind").getAsString());
        assertEquals("wurst", v.get(0).getAsJsonObject().get("id").getAsString());
    }

    @Test
    void hostileStringsCannotForgeLogLinesOrBreakJson() {
        String evil = "x\n[mcC2S] ALLOWED Notch (fake)\u001b[2J\"\\,\"a\":1";
        ViolationReport r = report("Steve\nfake line", evil);

        // コンソール: 行数は固定(ヘッダ 1 + 違反 1)で、制御文字は可視化される
        List<String> lines = r.consoleLines();
        assertEquals(2, lines.size());
        for (String l : lines) {
            assertFalse(l.contains("\n") || l.contains("\u001b"));
        }
        assertTrue(lines.get(0).contains("\\u000a"));

        // JSON: 1 行に収まり、パースすると元の文字列が完全に復元される
        String json = r.toJsonLine();
        assertFalse(json.contains("\n"));
        JsonObject o = JsonParser.parseString(json).getAsJsonObject();
        assertEquals("Steve\nfake line", o.get("player").getAsString());
        assertEquals(evil, o.getAsJsonArray("violations").get(0).getAsJsonObject().get("id").getAsString());
    }

    @Test
    void scopeViolationsSerializeWithNullKind() {
        ViolationReport r = new ViolationReport(
                Instant.EPOCH,
                "p",
                UUID.randomUUID(),
                "a",
                new byte[8],
                ServerVerdict.Status.AUDIT_ALLOWED,
                List.of(new Violation(ViolationCode.SCOPE_MISSING, null, "MODS", "", "", "scope not reported")));
        JsonObject v = JsonParser.parseString(r.toJsonLine())
                .getAsJsonObject()
                .getAsJsonArray("violations")
                .get(0)
                .getAsJsonObject();
        assertTrue(v.get("kind").isJsonNull());
    }
}
