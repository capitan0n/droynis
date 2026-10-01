package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class UsbDebuggingCheckTest {

    private suspend fun statusFor(adbEnabled: Reading<String>): Status =
        UsbDebuggingCheck(FakeSettings(mapOf("adb_enabled" to adbEnabled))).run(scanContext()).status

    @Test
    fun `enabled is a FAIL`() = runTest {
        assertEquals(Status.FAIL, statusFor(value("1")))
        assertEquals(Status.FAIL, statusFor(value(" 1\n")))
    }

    @Test
    fun `disabled is a PASS`() = runTest {
        assertEquals(Status.PASS, statusFor(value("0")))
    }

    @Test
    fun `missing, unreadable or unexpected values are UNKNOWN, never PASS`() = runTest {
        assertEquals(Status.UNKNOWN, statusFor(unavailable("not set")))
        assertEquals(Status.UNKNOWN, statusFor(unavailable("access denied")))
        assertEquals(Status.UNKNOWN, statusFor(value("true")))
        assertEquals(Status.UNKNOWN, statusFor(value("")))
    }

    @Test
    fun `evidence records the raw value and where it came from`() = runTest {
        val source = Source("Settings.Global \"adb_enabled\"")
        val check = UsbDebuggingCheck(FakeSettings(mapOf("adb_enabled" to Reading.Value("1", source))))

        val outcome = check.run(scanContext())

        assertEquals(listOf(Evidence("adb_enabled", "1", source)), outcome.evidence)
    }
}
