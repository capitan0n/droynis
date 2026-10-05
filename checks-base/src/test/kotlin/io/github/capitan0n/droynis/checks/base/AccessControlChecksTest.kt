package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class AccessControlChecksTest {

    @ParameterizedTest(name = "screen_off_timeout={0} -> {1}")
    @CsvSource(
        "15000, PASS, Screen turns off after 15 seconds",
        "60000, PASS, Screen turns off after 1 minute",
        "120000, PASS, Screen turns off after 2 minutes",
        "300000, FAIL, Screen stays on for 5 minutes",
        "90000, PASS, Screen turns off after 90 seconds",
        "2147483647, FAIL, Screen never turns off by itself",
        "-1, FAIL, Screen never turns off by itself",
    )
    fun `screen timeout`(raw: String, status: Status, summary: String) = runTest {
        val outcome = ScreenTimeoutCheck(FakeSettings(system = mapOf("screen_off_timeout" to value(raw)))).outcome()

        assertEquals(status, outcome.status)
        assertEquals(summary, outcome.summary)
    }

    @Test
    fun `screen timeout without a readable number is UNKNOWN`() = runTest {
        assertEquals(Status.UNKNOWN, ScreenTimeoutCheck(FakeSettings()).status())
        assertEquals(
            Status.UNKNOWN,
            ScreenTimeoutCheck(FakeSettings(system = mapOf("screen_off_timeout" to value("soon")))).status(),
        )
    }

    @Test
    fun `developer options`() = runTest {
        suspend fun status(raw: String?, sdk: Int = 36) = DeveloperOptionsCheck(
            FakeSettings(global = mapOf("development_settings_enabled" to value(raw))),
        ).run(scanContext(sdk = sdk)).status

        assertEquals(Status.FAIL, status("1"))
        assertEquals(Status.PASS, status("0"))
        assertEquals(Status.PASS, status(null)) // never toggled
        assertEquals(Status.UNKNOWN, status("yes"))
        assertEquals(
            Status.UNKNOWN,
            DeveloperOptionsCheck(FakeSettings(global = mapOf("development_settings_enabled" to unavailable()))).status(),
        )

        // Android 17 may redact the key to "0" for apps; "1" and unset are still real.
        assertEquals(Status.UNKNOWN, status("0", sdk = 37))
        assertEquals(Status.FAIL, status("1", sdk = 37))
        assertEquals(Status.PASS, status(null, sdk = 37))
    }

    @Test
    fun `password visibility`() = runTest {
        suspend fun status(raw: String?) =
            PasswordVisibilityCheck(FakeSettings(system = mapOf("show_password" to value(raw)))).status()

        assertEquals(Status.FAIL, status("1"))
        assertEquals(Status.FAIL, status(null)) // Android's default is to show
        assertEquals(Status.PASS, status("0"))
        assertEquals(Status.UNKNOWN, status("maybe"))
        assertEquals(
            Status.UNKNOWN,
            PasswordVisibilityCheck(FakeSettings(system = mapOf("show_password" to unavailable()))).status(),
        )
    }

    @Test
    fun `lock screen notifications`() = runTest {
        suspend fun outcome(show: String?, content: String?) = LockScreenNotificationsCheck(
            FakeSettings(
                secure = mapOf(
                    "lock_screen_show_notifications" to value(show),
                    "lock_screen_allow_private_notifications" to value(content),
                ),
            ),
        ).outcome()

        assertEquals(Status.PASS, outcome("0", "1").status) // nothing shown at all
        assertEquals(Status.PASS, outcome("1", "0").status) // shown, content hidden
        assertEquals(Status.FAIL, outcome("1", "1").status)
        assertEquals(Status.FAIL, outcome(null, "1").status) // shown by default
        assertEquals(Status.UNKNOWN, outcome("1", null).status)
        assertEquals(Status.UNKNOWN, outcome("2", "0").status)
        assertEquals(2, outcome("1", "1").evidence.size)

        val unreadable = LockScreenNotificationsCheck(
            FakeSettings(secure = mapOf("lock_screen_show_notifications" to unavailable("access denied"))),
        )
        assertEquals(Status.UNKNOWN, unreadable.status())
    }

    @Test
    fun `wireless debugging`() = runTest {
        fun check(raw: String?) = WirelessDebuggingCheck(FakeSettings(global = mapOf("adb_wifi_enabled" to value(raw))))

        assertEquals(Status.FAIL, check("1").status())
        assertEquals(Status.PASS, check("0").status())
        assertEquals(Status.UNKNOWN, check(null).status())
        assertEquals(
            Status.UNKNOWN,
            WirelessDebuggingCheck(FakeSettings(global = mapOf("adb_wifi_enabled" to unavailable("access denied")))).status(),
        )
        assertEquals(30, WirelessDebuggingCheck(FakeSettings()).spec.minSdk)
    }
}
