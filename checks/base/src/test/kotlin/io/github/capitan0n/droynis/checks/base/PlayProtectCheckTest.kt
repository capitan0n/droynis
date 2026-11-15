package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.PlayProtectCheck.Companion.PACKAGE_VERIFIER_ENABLE
import io.github.capitan0n.droynis.checks.base.PlayProtectCheck.Companion.PACKAGE_VERIFIER_USER_CONSENT
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class PlayProtectCheckTest {

    private fun check(
        reading: io.github.capitan0n.droynis.core.Reading<String?>,
        consent: io.github.capitan0n.droynis.core.Reading<String?> = value(null),
    ) = PlayProtectCheck(FakeSettings(global = mapOf(PACKAGE_VERIFIER_ENABLE to reading, PACKAGE_VERIFIER_USER_CONSENT to consent)))

    @Test
    fun `the verifier on passes, off fails`() = runTest {
        assertEquals(Status.PASS, check(value("1")).run(scanContext()).status)

        val off = check(value("0")).run(scanContext())
        assertEquals(Status.FAIL, off.status)
        assertEquals("App scanning is off: apps install without a malware check", off.summary)
        assertEquals("0", off.evidence.first().value)
    }

    @Test
    fun `Play Protect's own switch decides where the master switch is unset`() = runTest {
        // Most phones never write the master switch: both test phones read it as not set.
        val on = check(value(null), consent = value("1")).run(scanContext())
        assertEquals(Status.PASS, on.status)
        assertEquals(listOf("(not set)", "1"), on.evidence.map { it.value })

        val off = check(value(null), consent = value("-1")).run(scanContext())
        assertEquals(Status.FAIL, off.status)
        assertEquals("Play Protect's app scanning is turned off: apps install without a malware check", off.summary)

        // Turned off in Play Protect while the master switch is on: still off.
        assertEquals(Status.FAIL, check(value("1"), consent = value("-1")).run(scanContext()).status)
        // The master switch off wins over a consent given earlier.
        assertEquals(Status.FAIL, check(value("0"), consent = value("1")).run(scanContext()).status)
        // Not asked yet, or hidden from apps: proves nothing.
        assertEquals(Status.UNKNOWN, check(value(null), consent = value("0")).run(scanContext()).status)
        assertEquals(Status.UNKNOWN, check(value(null), consent = unavailable("access denied")).run(scanContext()).status)
        assertEquals(Status.PASS, check(unavailable("access denied"), consent = value("1")).run(scanContext()).status)
    }

    @Test
    fun `an unset, unexpected or unreadable value never passes`() = runTest {
        assertEquals(Status.UNKNOWN, check(value(null)).run(scanContext()).status)
        assertEquals(Status.UNKNOWN, check(value("2")).run(scanContext()).status)
        assertEquals(Status.UNKNOWN, check(unavailable("access denied")).run(scanContext()).status)
        assertEquals(Status.UNSUPPORTED, check(unsupported("no such setting")).run(scanContext()).status)
    }
}
