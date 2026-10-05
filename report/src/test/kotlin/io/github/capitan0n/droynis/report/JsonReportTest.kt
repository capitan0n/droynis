package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonReportTest {

    private val context = ScanContext(ZonedDateTime.of(2026, 10, 5, 14, 2, 0, 0, ZoneOffset.ofHours(3)), sdkInt = 36)

    private fun finding(id: String, status: Status, severity: Severity, summary: String, evidence: List<Evidence>) = Finding(
        spec = CheckSpec(id, Category.DEVICE_INTEGRITY, "Title of $id", severity, "Why.", Remediation("Fix \"it\".")),
        status = status,
        severity = severity,
        summary = summary,
        evidence = evidence,
        elapsedMillis = 12,
    )

    private val findings = listOf(
        finding(
            "INTG-1040", Status.FAIL, Severity.CRITICAL, "The bootloader is unlocked",
            listOf(Evidence("Device locked (attested)", "false", Source("Key attestation"), note = "line 1\nline 2")),
        ),
        finding(
            "ACCS-2011", Status.PASS, Severity.WARNING, "Path C:\\temp \"quoted\"\ttab",
            listOf(Evidence("adb_enabled", null, Source("Settings.Global", Grant.DUMP), note = "bell\u0007")),
        ),
    )

    private val json = JsonReport.render(
        context,
        findings,
        HardeningIndex.of(findings),
        listOf(DeviceFact("model", "Model", "FP6")),
        "0.4.0",
    )

    @Test
    fun `report is valid JSON with the documented layout`() {
        val root = MiniJson.parse(json) as Map<*, *>

        assertEquals("droynis-report", root["schema"])
        assertEquals(1L, root["schemaVersion"])
        assertEquals("2026-10-05T14:02:00+03:00", (root["scan"] as Map<*, *>)["startedAt"])
        assertEquals(mapOf("model" to "FP6"), root["device"])

        val score = root["score"] as Map<*, *>
        assertEquals(33L, score["value"]) // 5 / 15; the cap never raises a score
        assertEquals(33L, score["uncapped"])
        assertEquals("F", score["grade"])
        assertEquals(listOf("INTG-1040"), score["cappedBy"])
        assertEquals(mapOf("CRITICAL" to 1L), score["failed"])

        val first = (root["findings"] as List<*>).first() as Map<*, *>
        assertEquals("INTG-1040", first["id"])
        assertEquals("CRITICAL", first["verdict"])
        assertEquals("Fix \"it\".", first["remediation"])
    }

    @Test
    fun `strings are escaped and unreadable values are null`() {
        val second = ((MiniJson.parse(json) as Map<*, *>)["findings"] as List<*>)[1] as Map<*, *>
        val evidence = (second["evidence"] as List<*>).single() as Map<*, *>

        assertEquals("Path C:\\temp \"quoted\"\ttab", second["summary"])
        assertEquals(null, evidence["value"])
        assertEquals("DUMP", evidence["grant"])
        assertEquals("bell\u0007", evidence["note"])
        assertTrue("\\u0007" in json)
    }

    @Test
    fun `output is stable and line-oriented for diffing`() {
        assertEquals(json, JsonReport.render(context, findings, HardeningIndex.of(findings), listOf(DeviceFact("model", "Model", "FP6")), "0.4.0"))
        assertTrue("\n    \"schemaVersion\"" !in json) // two-space indent at the top level
        assertTrue("\n  \"schemaVersion\": 1,\n" in json)
        assertTrue(json.endsWith("}\n"))
    }
}

/** A strict little JSON parser, so the test checks well-formedness without a library. */
private object MiniJson {
    fun parse(text: String): Any? {
        val parser = Parser(text)
        val value = parser.value()
        parser.skipSpace()
        check(parser.pos == text.length) { "trailing data at ${parser.pos}" }
        return value
    }

    private class Parser(val s: String) {
        var pos = 0

        fun skipSpace() {
            while (pos < s.length && s[pos] in " \n\r\t") pos++
        }

        fun value(): Any? {
            skipSpace()
            return when (val c = s[pos]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) num() else error("unexpected '$c' at $pos")
            }
        }

        private fun literal(word: String, result: Any?): Any? {
            check(s.startsWith(word, pos)) { "bad literal at $pos" }
            pos += word.length
            return result
        }

        private fun num(): Long {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && s[pos].isDigit()) pos++
            return s.substring(start, pos).toLong()
        }

        private fun str(): String {
            pos++ // opening quote
            val out = StringBuilder()
            while (true) {
                val c = s[pos++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> when (val e = s[pos++]) {
                        '"', '\\', '/' -> out.append(e)
                        'n' -> out.append('\n')
                        'r' -> out.append('\r')
                        't' -> out.append('\t')
                        'u' -> out.append(s.substring(pos, pos + 4).toInt(16).toChar()).also { pos += 4 }
                        else -> error("bad escape \\$e")
                    }
                    c < ' ' -> error("raw control character in string at ${pos - 1}")
                    else -> out.append(c)
                }
            }
        }

        private fun arr(): List<Any?> {
            pos++
            val items = mutableListOf<Any?>()
            skipSpace()
            if (s[pos] == ']') return items.also { pos++ }
            while (true) {
                items += value()
                skipSpace()
                when (s[pos++]) {
                    ',' -> continue
                    ']' -> return items
                    else -> error("expected , or ] at ${pos - 1}")
                }
            }
        }

        private fun obj(): Map<String, Any?> {
            pos++
            val map = linkedMapOf<String, Any?>()
            skipSpace()
            if (s[pos] == '}') return map.also { pos++ }
            while (true) {
                skipSpace()
                val key = str()
                skipSpace()
                check(s[pos++] == ':') { "expected : at ${pos - 1}" }
                map[key] = value()
                skipSpace()
                when (s[pos++]) {
                    ',' -> continue
                    '}' -> return map
                    else -> error("expected , or } at ${pos - 1}")
                }
            }
        }
    }
}
