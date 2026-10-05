package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class UsbDebuggingCheckTest {

    private suspend fun statusFor(adbEnabled: Reading<String?>, sdk: Int = 36): Status =
        UsbDebuggingCheck(FakeSettings(mapOf("adb_enabled" to adbEnabled))).run(scanContext(sdk = sdk)).status

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
    fun `from Android 17 a 0 may be the redaction placeholder, so it is UNKNOWN`() = runTest {
        val outcome = UsbDebuggingCheck(FakeSettings(mapOf("adb_enabled" to value("0")))).run(scanContext(sdk = 37))

        assertEquals(Status.UNKNOWN, outcome.status)
        assertTrue(outcome.summary.startsWith("Can't be verified"))
        assertTrue(outcome.evidence.single().note!!.contains("Android 17"))
        assertEquals(Status.FAIL, statusFor(value("1"), sdk = 37)) // a real value is never redacted to 1
    }

    @Test
    fun `missing, unreadable or unexpected values are UNKNOWN, never PASS`() = runTest {
        assertEquals(Status.UNKNOWN, statusFor(value(null)))
        assertEquals(Status.UNKNOWN, statusFor(unavailable("access denied")))
        assertEquals(Status.UNKNOWN, statusFor(value("true")))
        assertEquals(Status.UNKNOWN, statusFor(value("")))
    }

    @Test
    fun `evidence records the raw value and where it came from`() = runTest {
        val source = Source("Settings.Global \"adb_enabled\"")
        val check = UsbDebuggingCheck(FakeSettings(mapOf("adb_enabled" to Reading.Value("1", source))))

        assertEquals(listOf(Evidence("adb_enabled", "1", source)), check.outcome().evidence)
    }

    @Test
    fun `an unset key is shown as such in the evidence`() = runTest {
        val evidence = UsbDebuggingCheck(FakeSettings()).outcome().evidence.single()

        assertEquals("(not set)", evidence.value)
    }
}
