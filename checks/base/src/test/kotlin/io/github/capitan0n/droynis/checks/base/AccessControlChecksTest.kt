package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
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
            FakeUsb(),
        ).run(scanContext(sdk = sdk)).status

        assertEquals(Status.FAIL, status("1"))
        assertEquals(Status.PASS, status("0"))
        assertEquals(Status.PASS, status(null)) // never toggled
        assertEquals(Status.UNKNOWN, status("yes"))
        assertEquals(
            Status.UNKNOWN,
            DeveloperOptionsCheck(FakeSettings(global = mapOf("development_settings_enabled" to unavailable())), FakeUsb()).status(),
        )

        // Android 17 may redact the key to "0" for apps; "1" and unset are still real.
        assertEquals(Status.UNKNOWN, status("0", sdk = 37))
        assertEquals(Status.FAIL, status("1", sdk = 37))
        assertEquals(Status.PASS, status(null, sdk = 37))
        val shell = Reading.Value<String?>("0", Source("settings get global development_settings_enabled", Grant.SHIZUKU))
        assertEquals(
            Status.PASS,
            DeveloperOptionsCheck(FakeSettings(global = mapOf("development_settings_enabled" to shell)), FakeUsb())
                .run(scanContext(sdk = 37)).status,
        )
    }

    @Test
    fun `on Android 17 USB or wireless debugging seen on proves developer options on`() = runTest {
        suspend fun outcome(
            adb: String? = "0",
            wifiAdb: Reading<String?> = value("0"),
            usb: Reading<UsbState?> = value(null),
            sdk: Int = 37,
        ) = DeveloperOptionsCheck(
            FakeSettings(
                global = mapOf(
                    "development_settings_enabled" to value("0"),
                    "adb_enabled" to value(adb),
                    "adb_wifi_enabled" to wifiAdb,
                ),
            ),
            FakeUsb(usb),
        ).run(scanContext(sdk = sdk))

        assertEquals("Developer options are on: wireless debugging is on", outcome(wifiAdb = value("1")).summary)
        assertEquals(Status.FAIL, outcome(wifiAdb = value("1")).status)
        // A redacting platform answers "0", so a "1" is real.
        assertEquals("Developer options are on: USB debugging is on", outcome(adb = "1").summary)
        assertEquals(
            "Developer options are on: a connected computer is using adb",
            outcome(usb = value(UsbState(connected = true, adb = true))).summary,
        )

        val none = outcome(usb = value(UsbState(connected = true, adb = false)))
        assertEquals(Status.UNKNOWN, none.status)
        assertTrue(none.summary.startsWith("Can't be verified"))
        val evidence = none.evidence.associateBy { it.label }
        assertTrue(evidence.getValue("adb_enabled").note!!.contains("Android 17"))
        assertEquals("0", evidence.getValue("adb_wifi_enabled").value)
        assertEquals(Status.UNKNOWN, outcome(wifiAdb = unavailable("access denied")).status)
        assertEquals(Status.UNKNOWN, outcome(usb = value(UsbState(connected = false, adb = true))).status) // stale

        // Before Android 17 a "0" is real and nothing else is consulted.
        assertEquals(Status.PASS, outcome(wifiAdb = value("1"), sdk = 36).status)
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
    fun `notification history`() = runTest {
        fun check(raw: Reading<String?>) =
            NotificationHistoryCheck(FakeSettings(secure = mapOf("notification_history_enabled" to raw)))

        assertEquals(Status.FAIL, check(value("1")).status())
        assertEquals(Status.PASS, check(value("0")).status())
        assertEquals(Status.PASS, check(value(null)).status()) // the platform's default is off
        assertEquals(Status.UNKNOWN, check(value("on")).status())
        assertEquals(Status.UNKNOWN, check(unavailable("access denied")).status())

        val failed = check(value("1")).outcome()
        assertEquals("Notification history is on", failed.summary)
        assertEquals(listOf("1"), failed.evidence.map { it.value })
        assertEquals(30, check(value(null)).spec.minSdk)
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

        // An app the user installed counts; a preinstalled one, like Samsung's Knox Guard financing
        // lock, may answer to someone else, and so may an admin when the app list can't be read.
        fun installed(pkg: String, system: Boolean) =
            InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = null, targetSdk = 30)
        val prey = admin("com.prey", lock = true, wipe = true)
        assertEquals(Status.PASS, check(prey, apps = listOf(installed("com.prey", system = false))).status())
        val knoxGuard = admin("com.samsung.android.kgclient", lock = true, wipe = true)
        val preinstalled = check(knoxGuard, apps = listOf(installed("com.samsung.android.kgclient", system = true))).outcome()
        assertEquals(Status.UNKNOWN, preinstalled.status)
        assertTrue(preinstalled.evidence.single().note!!.contains("may answer to the maker"))
        assertEquals(
            Status.UNKNOWN,
            RemoteLockCheck(FakePolicy(admins = value(listOf(prey))), FakePackages(unavailable("denied"))).status(),
        )
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

    @Test
    fun `microG is not taken for Find Hub`() = runTest {
        // /e/OS: microG uses Play services' package name, but has no find-my-device service.
        val gms = InstalledApp("com.google.android.gms", isSystem = true, isDebuggable = false, installer = null, targetSdk = 35)
        fun check(label: String) =
            RemoteLockCheck(FakePolicy(admins = value(emptyList())), FakePackages(value(listOf(gms)), mapOf(gms.packageName to label)))

        val microG = check("microG Services").outcome()
        assertEquals(Status.FAIL, microG.status)
        val evidence = microG.evidence.single { it.label == "Google Play services" }
        assertEquals("microG Services (com.google.android.gms)", evidence.value)
        assertEquals("microG, which has no find-my-device service", evidence.note)
        assertTrue(microG.evidence.none { it.label == "Find-my-device service" })

        assertEquals(Status.UNKNOWN, check("Google Play services").status())
    }
}
