package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class AppsChecksTest {

    private val talkback = AppRef("com.google.android.marvin.talkback", "TalkBack")

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)
    private val tasker = AppRef("net.dinglisch.android.taskerm", "Tasker")

    @Test
    fun `accessibility services`() = runTest {
        assertEquals(Status.PASS, AccessibilityServicesCheck(FakeAccessibility(), FakePackages()).status())

        val outcome = AccessibilityServicesCheck(FakeAccessibility(value(listOf(talkback, tasker))), FakePackages()).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("2 accessibility services enabled: TalkBack and Tasker", outcome.summary)
        assertEquals(2, outcome.evidence.size)

        assertEquals(Status.UNKNOWN, AccessibilityServicesCheck(FakeAccessibility(unavailable()), FakePackages()).status())
    }

    @Test
    fun `a sideloaded app with accessibility is a warning`() = runTest {
        val apps = FakePackages(value(listOf(app(talkback.packageName, system = true), app(tasker.packageName, installer = null))))
        val outcome = AccessibilityServicesCheck(FakeAccessibility(value(listOf(talkback, tasker))), apps).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals("2 accessibility services enabled: TalkBack and Tasker; Tasker comes from outside an app store", outcome.summary)
        assertEquals(listOf("came with the phone", "installed from outside an app store"), outcome.evidence.map { it.note })
    }

    @Test
    fun `device admins`() = runTest {
        assertEquals(Status.PASS, DeviceAdminsCheck(FakePolicy(), FakePackages()).status())

        val owner = AdminApp(AppRef("com.example.mdm", "Work MDM"), isDeviceOwner = true, isProfileOwner = false)
        val outcome = DeviceAdminsCheck(FakePolicy(admins = value(listOf(owner))), FakePackages()).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertTrue("managed by an organization" in outcome.summary)
        assertTrue(outcome.evidence.single().value!!.endsWith("device owner)"))

        // Samsung's Knox Guard comes with the phone: listed, not counted. A sideloaded admin is a warning.
        val knoxGuard = AdminApp(AppRef("com.samsung.android.kgclient", "Device Services"), isDeviceOwner = false, isProfileOwner = false)
        val locker = AdminApp(AppRef("org.example.locker", "Locker"), isDeviceOwner = false, isProfileOwner = false)
        val apps = FakePackages(value(listOf(app(knoxGuard.app.packageName, system = true), app(locker.app.packageName, installer = null))))
        val preinstalled = DeviceAdminsCheck(FakePolicy(admins = value(listOf(knoxGuard))), apps).outcome()
        assertEquals(Status.PASS, preinstalled.status)
        assertEquals("came with the phone; not counted", preinstalled.evidence.single().note)
        val sideloaded = DeviceAdminsCheck(FakePolicy(admins = value(listOf(knoxGuard, locker))), apps).outcome()
        assertEquals("1 device admin app: Locker; Locker comes from outside an app store", sideloaded.summary)
        assertEquals(Severity.WARNING, sideloaded.escalation)
    }

    @Test
    fun `notification access lists the listening apps`() = runTest {
        fun check(raw: Reading<String?>) = NotificationAccessCheck(
            FakeSettings(secure = mapOf("enabled_notification_listeners" to raw)),
            FakePackages(labels = mapOf("com.example.watch" to "Watch", "net.dinglisch.android.taskerm" to "Tasker")),
        )

        assertEquals(Status.PASS, check(value(null)).status())
        assertEquals(Status.PASS, check(value("")).status())
        assertEquals(Status.UNKNOWN, check(unavailable("access denied")).status())

        val outcome = check(
            value("com.example.watch/.Listener:net.dinglisch.android.taskerm/net.dinglisch.Listener:com.example.watch/.Other"),
        ).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 apps can read your notifications: Watch and Tasker", outcome.summary)
        assertEquals("Watch (com.example.watch)", outcome.evidence.first().value)
    }

    @Test
    fun `notification listeners that came with the phone do not count`() = runTest {
        val listeners = FakeSettings(
            secure = mapOf("enabled_notification_listeners" to value("com.sec.android.app.launcher/.Badges:org.example.spy/.L")),
        )
        val launcherOnly = FakePackages(value(listOf(app("com.sec.android.app.launcher", system = true))))
        val stock = NotificationAccessCheck(
            FakeSettings(secure = mapOf("enabled_notification_listeners" to value("com.sec.android.app.launcher/.Badges"))),
            launcherOnly,
        ).outcome()
        assertEquals(Status.PASS, stock.status)
        assertEquals("Only apps that came with the phone can read your notifications", stock.summary)

        val withSpy = FakePackages(value(listOf(app("com.sec.android.app.launcher", system = true), app("org.example.spy", installer = null))))
        val outcome = NotificationAccessCheck(listeners, withSpy).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals("came with the phone; not counted", outcome.evidence.first().note)
    }

    @Test
    fun `listener packages are parsed from flattened component names`() {
        assertEquals(emptyList(), NotificationAccessCheck.listenerPackages(null))
        assertEquals(listOf("a.b", "c.d"), NotificationAccessCheck.listenerPackages("a.b/.X: c.d/c.d.Y ::a.b/.Z"))
    }

    @Test
    fun `third-party keyboards need attention, built-in ones pass`() = runTest {
        val gboard = Keyboard(AppRef("com.google.android.inputmethod.latin", "Gboard"), isSystem = true)
        val floris = Keyboard(AppRef("dev.patrickgold.florisboard", "FlorisBoard"), isSystem = false)

        val builtIn = KeyboardAppsCheck(FakeInputMethods(value(listOf(gboard)))).outcome()
        assertEquals(Status.PASS, builtIn.status)
        assertEquals("Only built-in keyboards are enabled: Gboard", builtIn.summary)

        val mixed = KeyboardAppsCheck(FakeInputMethods(value(listOf(gboard, floris)))).outcome()
        assertEquals(Status.FAIL, mixed.status)
        assertEquals("1 third-party keyboard enabled: FlorisBoard", mixed.summary)
        assertEquals(listOf("built-in", "third-party"), mixed.evidence.map { it.value!!.substringAfterLast(", ") })

        assertEquals(Status.UNKNOWN, KeyboardAppsCheck(FakeInputMethods(value(emptyList()))).status())
        assertEquals(Status.UNKNOWN, KeyboardAppsCheck(FakeInputMethods(unavailable())).status())
    }

    @Test
    fun `apps built for old android`() = runTest {
        val apps = listOf(
            InstalledApp("org.legacy.app", isSystem = false, isDebuggable = false, installer = null, targetSdk = 22),
            InstalledApp("org.modern.app", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35),
            InstalledApp("com.android.legacy", isSystem = true, isDebuggable = false, installer = null, targetSdk = 19),
        )
        val outcome = OutdatedAppsCheck(FakePackages(value(apps), mapOf("org.legacy.app" to "Legacy"))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app built for Android 8.1 or older: Legacy", outcome.summary)
        assertEquals(Status.PASS, OutdatedAppsCheck(FakePackages(value(apps.drop(1)))).status())
        assertEquals(Status.UNKNOWN, OutdatedAppsCheck(FakePackages(unavailable())).status())
    }

    @Test
    fun `debuggable apps`() = runTest {
        val apps = listOf(
            InstalledApp("org.example.dev", isSystem = false, isDebuggable = true, installer = null, targetSdk = 35),
            InstalledApp("org.example.release", isSystem = false, isDebuggable = false, installer = "org.fdroid.fdroid", targetSdk = 35),
        )
        val outcome = DebuggableAppsCheck(FakePackages(value(apps), mapOf("org.example.dev" to "Dev Build"))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 debuggable app: Dev Build", outcome.summary)
        assertEquals(Status.PASS, DebuggableAppsCheck(FakePackages(value(apps.drop(1)))).status())
        assertEquals(Status.UNKNOWN, DebuggableAppsCheck(FakePackages(unavailable())).status())
    }

    @Test
    fun `apps from unknown sources ignore system apps and known stores`() = runTest {
        val apps = listOf(
            InstalledApp("com.android.settings", isSystem = true, isDebuggable = false, installer = null, targetSdk = 35),
            InstalledApp("org.thoughtcrime.securesms", isSystem = false, isDebuggable = false, installer = "com.android.vending", targetSdk = 35),
            InstalledApp("org.schabi.newpipe", isSystem = false, isDebuggable = false, installer = "org.fdroid.fdroid", targetSdk = 35),
            InstalledApp("com.example.apk", isSystem = false, isDebuggable = false, installer = "com.google.android.packageinstaller", targetSdk = 35),
            InstalledApp("com.example.adb", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35),
        )
        val outcome = UnknownSourceAppsCheck(FakePackages(value(apps))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 apps from outside an app store: com.example.apk and com.example.adb", outcome.summary)
        assertEquals(Status.PASS, UnknownSourceAppsCheck(FakePackages(value(apps.take(3)))).status())
    }
}
