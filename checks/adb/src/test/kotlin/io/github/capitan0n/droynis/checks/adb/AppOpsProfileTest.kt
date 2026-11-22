package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AppOpsProfileTest {
    private val source = Source("dumpsys appops")

    private val blocks = """
        |  Uid u0a123:
        |    Package org.example.shared:
        |      CAMERA (ignore):
        |  Uid u10a123:
        |    Package org.example.shared:
        |      CAMERA (allow):
        |        Access: [bg-s] 2026-10-05 11:00:00.000 (-1s0ms)
        |  Uid 1000:
        |    Package android:
        |      WAKE_LOCK (allow):
        |        Access: [pers-s] 2026-10-05 11:00:00.000 (-1s0ms)
        |  Uid u10a321:
        |    GET_USAGE_STATS: mode=allow
    """.trimMargin()

    @Test
    fun `modes and history only see the scanning profile even for the same package`() {
        val ops = setOf("CAMERA", "GET_USAGE_STATS")
        for (heading in listOf("AppOps Uid Op State\n", "Current AppOps Service state:\n")) {
            val raw = Reading.Value(heading + blocks + "\nOther section:\n  Uid u0a555:\n", source)
            val primary = assertIs<Reading.Value<String>>(appOpsForProfile(raw, 10_123)).value
            val work = assertIs<Reading.Value<String>>(appOpsForProfile(raw, 1_010_123)).value

            val modes = assertIs<AppOpModes.Result.Parsed>(AppOpModes.allowed(primary, ops))
            assertEquals(2, modes.packages)
            assertEquals(emptyList(), modes.grants)
            val workModes = assertIs<AppOpModes.Result.Parsed>(AppOpModes.allowed(work, ops))
            assertEquals(1, workModes.packages)
            assertEquals(listOf("u10a123", "u10a321"), workModes.grants.map { it.uid })

            val history = assertIs<AppOpsDump.Result.Parsed>(AppOpsDump.parse(primary))
            assertEquals(listOf("WAKE_LOCK"), history.accesses.map { it.op })
            val workHistory = assertIs<AppOpsDump.Result.Parsed>(AppOpsDump.parse(work))
            assertEquals(listOf("CAMERA"), workHistory.accesses.map { it.op })
        }
    }

    @Test
    fun `unknown UID format or missing profile is unavailable`() {
        val bad = blocks.replace("Uid u10a123:", "Uid unexpected:")
        assertIs<Reading.Unavailable>(appOpsForProfile(Reading.Value(bad, source), 10_123))
        assertIs<Reading.Unavailable>(appOpsForProfile(Reading.Value(blocks, source), 1_110_123))
    }
}
