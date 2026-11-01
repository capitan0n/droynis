package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.PlayProtectCheck.Companion.PACKAGE_VERIFIER_ENABLE
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class PlayProtectCheckTest {

    private fun check(reading: io.github.capitan0n.droynis.core.Reading<String?>) =
        PlayProtectCheck(FakeSettings(global = mapOf(PACKAGE_VERIFIER_ENABLE to reading)))

    @Test
    fun `the verifier on passes, off fails`() = runTest {
        assertEquals(Status.PASS, check(value("1")).run(scanContext()).status)

        val off = check(value("0")).run(scanContext())
        assertEquals(Status.FAIL, off.status)
        assertEquals("App scanning is off: apps install without a malware check", off.summary)
        assertEquals("0", off.evidence.single().value)
    }

    @Test
    fun `an unset, unexpected or unreadable value never passes`() = runTest {
        assertEquals(Status.UNKNOWN, check(value(null)).run(scanContext()).status)
        assertEquals(Status.UNKNOWN, check(value("2")).run(scanContext()).status)
        assertEquals(Status.UNKNOWN, check(unavailable("access denied")).run(scanContext()).status)
        assertEquals(Status.UNSUPPORTED, check(unsupported("no such setting")).run(scanContext()).status)
    }
}
