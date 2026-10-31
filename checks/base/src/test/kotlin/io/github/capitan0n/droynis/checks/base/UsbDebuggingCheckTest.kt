package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class UsbDebuggingCheckTest {

    private fun check(adbEnabled: Reading<String?>?, usb: Reading<UsbState?> = value(null)) = UsbDebuggingCheck(
        FakeSettings(adbEnabled?.let { mapOf("adb_enabled" to it) }.orEmpty()),
        FakeUsb(usb),
    )

    private suspend fun statusFor(adbEnabled: Reading<String?>, sdk: Int = 36): Status =
        check(adbEnabled).run(scanContext(sdk = sdk)).status

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
        val outcome = check(value("0")).run(scanContext(sdk = 37))

        assertEquals(Status.UNKNOWN, outcome.status)
        assertTrue(outcome.summary.startsWith("Can't be verified"))
        assertTrue(outcome.evidence.first().note!!.contains("Android 17"))
        assertEquals("no USB state reported since boot", outcome.evidence.last().value)
        assertEquals(Status.FAIL, statusFor(value("1"), sdk = 37)) // a real value is never redacted to 1
    }

    @Test
    fun `a 0 read through the Shizuku shell is real, so it is a PASS`() = runTest {
        val shell = Reading.Value<String?>("0", Source("settings get global adb_enabled", Grant.SHIZUKU))

        assertEquals(Status.PASS, statusFor(shell, sdk = 37))
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
        val check = check(Reading.Value("1", source))

        assertEquals(listOf(Evidence("adb_enabled", "1", source)), check.outcome().evidence)
    }

    @Test
    fun `an unset key is shown as such in the evidence`() = runTest {
        val evidence = check(null).outcome().evidence.single()

        assertEquals("(not set)", evidence.value)
    }

    @Test
    fun `from Android 17 a computer using adb over USB proves it is on`() = runTest {
        val outcome = check(value("0"), usb = value(UsbState(connected = true, adb = true))).run(scanContext(sdk = 37))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("USB debugging is on: a connected computer is using adb", outcome.summary)
        assertEquals("connected to a computer, using adb", outcome.evidence.last().value)
    }

    @Test
    fun `the USB state never proves it off, and is stale while unplugged`() = runTest {
        suspend fun status(usb: Reading<UsbState?>) = check(value("0"), usb).run(scanContext(sdk = 37)).status

        assertEquals(Status.UNKNOWN, status(value(UsbState(connected = true, adb = false))))
        // Unplugged, the last broadcast can describe an earlier connection.
        assertEquals(Status.UNKNOWN, status(value(UsbState(connected = false, adb = true))))
        assertEquals(Status.UNKNOWN, status(unavailable("receiver refused")))
    }

    @Test
    fun `below Android 17 the setting decides and the USB state isn't read`() = runTest {
        val usb = object : UsbProbe {
            override fun state(): Reading<UsbState?> = error("not needed")
        }

        val outcome = UsbDebuggingCheck(FakeSettings(mapOf("adb_enabled" to value("0"))), usb).run(scanContext(sdk = 36))

        assertEquals(Status.PASS, outcome.status)
    }
}
