package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
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
        val shell = Reading.Value<String?>("0", Source("settings get global development_settings_enabled", Grant.SHIZUKU))
        assertEquals(
            Status.PASS,
            DeveloperOptionsCheck(FakeSettings(global = mapOf("development_settings_enabled" to shell)))
                .run(scanContext(sdk = 37)).status,
        )
    }

    @Test
    fun `stay awake while charging`() = runTest {
        suspend fun status(raw: String?) =
            StayAwakeCheck(FakeSettings(global = mapOf("stay_on_while_plugged_in" to value(raw)))).status()

        assertEquals(Status.PASS, status("0"))
        assertEquals(Status.FAIL, status("3")) // AC and USB
        assertEquals(Status.FAIL, status("15"))
        assertEquals(Status.UNKNOWN, status(null))
        assertEquals(Status.UNKNOWN, status("on"))
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

    @ParameterizedTest(name = "lock_screen_lock_after_timeout={0} -> {1}")
    @CsvSource(
        "0, PASS, Locks immediately after the screen turns off",
        "5000, PASS, Locks 5 seconds after the screen turns off",
        "30000, PASS, Locks 30 seconds after the screen turns off",
        "60000, FAIL, Stays unlocked for 1 minute after the screen turns off",
        "1800000, FAIL, Stays unlocked for 30 minutes after the screen turns off",
    )
    fun `lock after screen timeout`(raw: String, status: Status, summary: String) = runTest {
        val check = LockDelayCheck(
            FakeSettings(secure = mapOf("lock_screen_lock_after_timeout" to value(raw))),
            FakeKeyguard(value(true)),
        )

        val outcome = check.outcome()

        assertEquals(status, outcome.status)
        assertEquals(summary, outcome.summary)
    }

    @Test
    fun `lock delay is unknown when unset or unreadable, and N_A without a screen lock`() = runTest {
        fun check(raw: String?, secure: Boolean = true) = LockDelayCheck(
            FakeSettings(secure = mapOf("lock_screen_lock_after_timeout" to value(raw))),
            FakeKeyguard(value(secure)),
        )

        assertEquals(Status.UNKNOWN, check(null).status()) // the default lives in SystemUI, unreadable
        assertEquals(Status.UNKNOWN, check("soon").status())
        assertEquals(Status.UNKNOWN, check("-5").status())
        assertEquals(Status.UNSUPPORTED, check("600000", secure = false).status())
        val unreadableLock = LockDelayCheck(FakeSettings(), FakeKeyguard(unavailable()))
        assertEquals(Status.UNKNOWN, unreadableLock.status())
    }

    @Test
    fun `remote lock passes only on an admin that may lock and erase`() = runTest {
        fun admin(pkg: String, lock: Boolean?, wipe: Boolean?, deviceOwner: Boolean = false, profileOwner: Boolean = false) =
            AdminApp(AppRef(pkg, pkg.substringAfterLast('.')), deviceOwner, profileOwner, canLock = lock, canWipe = wipe)
        fun check(vararg admins: AdminApp, apps: List<InstalledApp> = emptyList()) =
            RemoteLockCheck(FakePolicy(admins = value(admins.toList())), FakePackages(value(apps)))

        val fmd = check(admin("de.nulide.findmydevice", lock = true, wipe = true)).outcome()
        assertEquals(Status.PASS, fmd.status)
        assertEquals("findmydevice can lock and erase this phone", fmd.summary)

        // Lock alone, or a work profile that can only remove itself, is not enough.
        assertEquals(Status.FAIL, check(admin("org.example.locker", lock = true, wipe = false)).status())
        assertEquals(Status.FAIL, check(admin("org.example.work", lock = true, wipe = true, profileOwner = true)).status())
        assertEquals(Status.PASS, check(admin("org.example.mdm", lock = true, wipe = true, deviceOwner = true, profileOwner = true)).status())
        assertEquals(Status.FAIL, check().status())
    }

    @Test
    fun `remote lock is unknown when a service may do it unseen`() = runTest {
        fun app(pkg: String, enabled: Boolean = true) =
            InstalledApp(pkg, isSystem = true, isDebuggable = false, installer = null, targetSdk = 37, isEnabled = enabled)
        fun check(apps: Reading<List<InstalledApp>>, admins: List<AdminApp> = emptyList()) =
            RemoteLockCheck(FakePolicy(admins = value(admins)), FakePackages(apps))

        val google = check(value(listOf(app("com.google.android.gms")))).outcome()
        assertEquals(Status.UNKNOWN, google.status)
        assertEquals(
            "Find Hub (Google Play services) can lock and erase a lost phone, but Android doesn't tell apps whether it is turned on",
            google.summary,
        )
        assertEquals(Status.FAIL, check(value(listOf(app("com.google.android.gms", enabled = false)))).status())
        assertEquals(Status.UNKNOWN, check(unavailable("denied")).status())

        val unreadable = AdminApp(AppRef("org.example.admin", "Admin"), false, false, canLock = null, canWipe = null)
        assertEquals(Status.UNKNOWN, check(value(emptyList()), listOf(unreadable)).status())
        assertEquals(Status.UNKNOWN, RemoteLockCheck(FakePolicy(admins = unavailable()), FakePackages()).status())
    }
}
