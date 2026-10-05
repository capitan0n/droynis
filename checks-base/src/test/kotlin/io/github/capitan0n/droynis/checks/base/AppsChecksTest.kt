package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class AppsChecksTest {

    private val talkback = AppRef("com.google.android.marvin.talkback", "TalkBack")
    private val tasker = AppRef("net.dinglisch.android.taskerm", "Tasker")

    @Test
    fun `accessibility services`() = runTest {
        assertEquals(Status.PASS, AccessibilityServicesCheck(FakeAccessibility()).status())

        val outcome = AccessibilityServicesCheck(FakeAccessibility(value(listOf(talkback, tasker)))).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 accessibility services enabled: TalkBack and Tasker", outcome.summary)
        assertEquals(2, outcome.evidence.size)

        assertEquals(Status.UNKNOWN, AccessibilityServicesCheck(FakeAccessibility(unavailable())).status())
    }

    @Test
    fun `device admins`() = runTest {
        assertEquals(Status.PASS, DeviceAdminsCheck(FakePolicy()).status())

        val owner = AdminApp(AppRef("com.example.mdm", "Work MDM"), isDeviceOwner = true, isProfileOwner = false)
        val outcome = DeviceAdminsCheck(FakePolicy(admins = value(listOf(owner)))).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertTrue("managed by an organization" in outcome.summary)
        assertTrue(outcome.evidence.single().value!!.endsWith("device owner)"))
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
    fun `debuggable apps`() = runTest {
        val apps = listOf(
            InstalledApp("org.example.dev", isSystem = false, isDebuggable = true, installer = null),
            InstalledApp("org.example.release", isSystem = false, isDebuggable = false, installer = "org.fdroid.fdroid"),
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
            InstalledApp("com.android.settings", isSystem = true, isDebuggable = false, installer = null),
            InstalledApp("org.thoughtcrime.securesms", isSystem = false, isDebuggable = false, installer = "com.android.vending"),
            InstalledApp("org.schabi.newpipe", isSystem = false, isDebuggable = false, installer = "org.fdroid.fdroid"),
            InstalledApp("com.example.apk", isSystem = false, isDebuggable = false, installer = "com.google.android.packageinstaller"),
            InstalledApp("com.example.adb", isSystem = false, isDebuggable = false, installer = null),
        )
        val outcome = UnknownSourceAppsCheck(FakePackages(value(apps))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 apps from outside an app store: com.example.apk and com.example.adb", outcome.summary)
        assertEquals(Status.PASS, UnknownSourceAppsCheck(FakePackages(value(apps.take(3)))).status())
    }
}
