package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

/** Apps using a built-in app's name (SUSP-5008). */
class SystemNameAppsCheckTest {

    private fun app(pkg: String, system: Boolean = false, installer: String? = null, enabled: Boolean = true) =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35, isEnabled = enabled)

    private val system = listOf(
        app("com.android.settings", system = true),
        app("com.sec.android.gallery3d", system = true),
        app("com.samsung.android.messaging", system = true),
        app("com.android.unnamed", system = true),
    )

    private val labels = mapOf(
        "com.android.settings" to "Settings",
        "com.sec.android.gallery3d" to "Gallery",
        "com.samsung.android.messaging" to "Messages",
        // What Magisk's "Hide the Magisk app" leaves: a random package called Settings.
        "wx.ys" to "Settings",
        "org.fossify.gallery" to "Gallery",
        "com.google.android.apps.messaging" to "Messages",
        "org.thoughtcrime.securesms" to "Signal",
    )

    private fun check(vararg user: InstalledApp, names: Map<String, String> = labels) =
        SystemNameAppsCheck(FakePackages(value(system + user), names))

    @Test
    fun `belongs to the suspicious apps and needs no privilege`() {
        val spec = check().spec
        assertEquals("SUSP-5008", spec.id)
        assertEquals(Category.SUSPICIOUS_APPS, spec.category)
        assertEquals(Severity.NOTICE, spec.severity)
        assertEquals(emptySet(), spec.requires)
    }

    @Test
    fun `a sideloaded app called Settings is a warning and named by its package`() = runTest {
        val outcome = check(app("wx.ys"), app("org.thoughtcrime.securesms", installer = "com.android.vending")).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals(
            "1 app from outside an app store uses the name of an app that came with the phone: Settings (wx.ys)",
            outcome.summary,
        )
        val row = outcome.evidence.single { it.label == "Uses a built-in app's name" }
        assertEquals("Settings (wx.ys)", row.value)
        assertEquals("same name as Settings (com.android.settings); installed from outside an app store", row.note)
        assertEquals("wx.ys", row.packageName)
        assertEquals(Trust.COUNTED, row.trust)
        assertEquals("2", outcome.evidence.single { it.label == "User apps inspected" }.value)
    }

    @Test
    fun `root can identify a renamed manager without hiding its installed name match`() = runTest {
        val installed = FakePackages(value(system + app("wx.ys")), labels)
        val packages = object : PackageInventory by installed {
            override fun installedLabel(packageName: String) = installed.label(packageName)
            override fun label(packageName: String) = if (packageName == "wx.ys") "Magisk manager (shown as Settings)" else installed.label(packageName)
        }
        val result = SystemNameAppsCheck(packages).outcome()
        assertEquals("Magisk manager (shown as Settings) (wx.ys)", result.evidence.single { it.packageName == "wx.ys" }.value)
    }

    @Test
    fun `a sideloaded replacement for an ordinary app is a notice`() = runTest {
        val outcome = check(app("org.fossify.gallery", installer = "com.google.android.packageinstaller")).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
    }

    @Test
    fun `a replacement from an app store is listed, not counted`() = runTest {
        // Google Messages on a Samsung phone, next to Samsung's own Messages.
        val outcome = check(
            app("com.google.android.apps.messaging", installer = "com.android.vending"),
            app("org.fossify.gallery", installer = "org.fdroid.fdroid"),
        ).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("${SystemNameAppsCheck.NONE} (2 apps from an app store listed, not counted)", outcome.summary)
        val rows = outcome.evidence.filter { it.label == "Uses a built-in app's name" }
        assertEquals(listOf(Trust.NOT_COUNTED, Trust.NOT_COUNTED), rows.map { it.trust })
        assertEquals("same name as Messages (com.samsung.android.messaging); from an app store; not counted", rows.last().note)
    }

    @Test
    fun `names are compared as they read on screen`() = runTest {
        assertEquals("settings", SystemNameAppsCheck.normalize("  SETTINGS\u200B "))
        assertEquals("google play services", SystemNameAppsCheck.normalize("Google\u00A0Play  services"))

        val disguised = check(app("a.b"), names = labels + ("a.b" to "settings\u200B")).outcome()
        assertEquals(Status.FAIL, disguised.status)
        // A disabled copy is still installed.
        assertEquals(Status.FAIL, check(app("wx.ys", enabled = false)).status())
    }

    @Test
    fun `apps without a label of their own never match`() = runTest {
        // Both are shown by their package name, which can't collide.
        val outcome = check(app("com.example.nolabel"), app("org.thoughtcrime.securesms")).outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals(SystemNameAppsCheck.NONE, outcome.summary)
        assertEquals(Status.PASS, check().status())
    }

    @Test
    fun `a trusted app is listed, not counted, and an unreadable list is unknown`() = runTest {
        val trusting = scanContext().copy(trustedApps = setOf("wx.ys"))
        val outcome = check(app("wx.ys")).run(trusting)
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust use a built-in app's name: Settings", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.last().trust)

        assertEquals(Status.UNKNOWN, SystemNameAppsCheck(FakePackages(unavailable("no QUERY_ALL_PACKAGES"))).status())
    }
}
