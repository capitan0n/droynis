package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.test.runTest

class RestartNfcAdbTimeoutTest {

    @Test
    fun `a phone up for more than a week fails`() = runTest {
        suspend fun outcome(up: Duration) = RestartCheck(FakeUptime(value(up))).outcome()

        val fresh = outcome(5.hours)
        assertEquals(Status.PASS, fresh.status)
        assertEquals("The phone restarted 5 hours ago", fresh.summary)
        assertEquals("5 hours", fresh.evidence.single().value)
        assertEquals("The phone restarted less than an hour ago", outcome(20.minutes).summary)
        assertEquals(Status.PASS, outcome(7.days).status)

        val stale = outcome(12.days + 3.hours)
        assertEquals(Status.FAIL, stale.status)
        assertEquals("The phone hasn't restarted for 12 days", stale.summary)

        assertEquals(Status.UNKNOWN, outcome((-1).milliseconds).status)
        assertEquals(Status.UNKNOWN, RestartCheck(FakeUptime(unavailable())).status())
    }

    @Test
    fun `NFC must need an unlock while it is on`() = runTest {
        suspend fun outcome(nfc: Boolean, secure: Reading<Boolean>) =
            SecureNfcCheck(FakeRadios(nfc = value(nfc), secureNfc = secure)).outcome()

        val open = outcome(true, value(false))
        assertEquals(Status.FAIL, open.status)
        assertEquals("NFC is on and works while the phone is locked", open.summary)
        assertEquals(Status.PASS, outcome(true, value(true)).status)
        // Off is safe whatever the switch says, even where the phone has no such switch.
        assertEquals(Status.PASS, outcome(false, value(false)).status)
        assertEquals(Status.PASS, outcome(false, unsupported("no Secure NFC option")).status)

        assertEquals(Status.UNSUPPORTED, outcome(true, unsupported("no Secure NFC option")).status)
        assertEquals(Status.UNKNOWN, outcome(true, unavailable("binder died")).status)
        assertEquals(
            Status.UNSUPPORTED,
            SecureNfcCheck(FakeRadios(nfc = unsupported("no NFC hardware"))).status(),
        )
        assertEquals(29, SecureNfcCheck(FakeRadios()).spec.minSdk)
    }

    @Test
    fun `computers allowed for debugging must expire`() = runTest {
        suspend fun outcome(raw: String?) = AdbAuthorizationTimeoutCheck(
            FakeSettings(global = mapOf(AdbAuthorizationTimeoutCheck.ADB_ALLOWED_CONNECTION_TIME to value(raw))),
        ).outcome()

        // Unset is Android's 7-day default, the value Developer options also writes back.
        val default = outcome(null)
        assertEquals(Status.PASS, default.status)
        assertEquals("(not set) (Android's default: 7 days)", default.evidence.single().value)
        assertEquals(Status.PASS, outcome("604800000").status)
        assertEquals(
            "A computer that hasn't connected for 1 day loses its debugging access",
            outcome("86400000").summary,
        )

        val never = outcome("0")
        assertEquals(Status.FAIL, never.status)
        assertEquals("Computers allowed for USB debugging keep their access for good", never.summary)
        assertEquals(
            "Computers allowed for USB debugging keep their access for 30 days without connecting",
            outcome("2592000000").summary,
        )

        assertEquals(Status.UNKNOWN, outcome("-5").status)
        assertEquals(Status.UNKNOWN, outcome("soon").status)
        val denied = AdbAuthorizationTimeoutCheck(
            FakeSettings(global = mapOf(AdbAuthorizationTimeoutCheck.ADB_ALLOWED_CONNECTION_TIME to unavailable("denied"))),
        )
        assertEquals(Status.UNKNOWN, denied.status())
        assertEquals(30, denied.spec.minSdk)
    }
}
