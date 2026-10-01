package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class SecurityPatchAgeCheckTest {

    // Scan date is 2026-10-01 throughout.
    @ParameterizedTest(name = "{0} -> {1} {2}")
    @CsvSource(
        "2026-10-01, PASS,",
        "2026-09-05, PASS,", // 26 days
        "2026-07-03, PASS,", // 90 days: still current
        "2026-07-02, FAIL,", // 91 days
        "2025-10-01, FAIL,", // 365 days: warning
        "2025-09-30, FAIL, CRITICAL", // 366 days: escalated
        "2019-08-05, FAIL, CRITICAL",
        "2026-11-15, PASS,", // 45 days ahead: OEM shipped early
        "2026-11-16, UNKNOWN,", // 46 days ahead: clock is wrong
    )
    fun `classifies by age`(patch: String, status: Status, escalation: Severity?) = runTest {
        val outcome = SecurityPatchAgeCheck(FakeBuildInfo(value(patch))).run(scanContext())

        assertEquals(status, outcome.status, outcome.summary)
        assertEquals(escalation, outcome.escalation)
    }

    @ParameterizedTest(name = "\"{0}\" -> UNKNOWN")
    @CsvSource("''", "' '", "unknown", "2026-13-01", "2026-09", "05.09.2026")
    fun `unparseable levels are UNKNOWN`(patch: String) = runTest {
        val outcome = SecurityPatchAgeCheck(FakeBuildInfo(value(patch))).run(scanContext())

        assertEquals(Status.UNKNOWN, outcome.status)
    }

    @Test
    fun `surrounding whitespace is tolerated`() = runTest {
        val outcome = SecurityPatchAgeCheck(FakeBuildInfo(value(" 2026-09-05\n"))).run(scanContext())

        assertEquals(Status.PASS, outcome.status)
    }

    @Test
    fun `an unreadable level is UNKNOWN`() = runTest {
        val outcome = SecurityPatchAgeCheck(FakeBuildInfo(unavailable())).run(scanContext())

        assertEquals(Status.UNKNOWN, outcome.status)
    }

    @Test
    fun `evidence shows the raw level and the reference date`() = runTest {
        val outcome = SecurityPatchAgeCheck(FakeBuildInfo(value("2026-09-05"))).run(scanContext())

        assertEquals(listOf("\"2026-09-05\"", "2026-10-01"), outcome.evidence.map { it.value })
    }
}
