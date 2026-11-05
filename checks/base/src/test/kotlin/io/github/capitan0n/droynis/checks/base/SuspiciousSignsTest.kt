package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.READ_SMS
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.RECEIVE_SMS
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.SYSTEM_ALERT_WINDOW
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * Hiding apps with powerful access (SUSP-5001), apps installed by another app (SUSP-5004),
 * banking-trojan permissions (SUSP-5005) and debug or test keys (SUSP-5006).
 */
class SuspiciousSignsTest {

    private val store = "org.fdroid.fdroid"
    private val packageInstaller = "com.google.android.packageinstaller"

    private fun app(pkg: String, installer: String? = store, system: Boolean = false, debuggable: Boolean = false) =
        InstalledApp(pkg, isSystem = system, isDebuggable = debuggable, installer = installer, targetSdk = 35)

    private fun footprint(
        pkg: String,
        hidden: Boolean = false,
        accessibility: Boolean = false,
        requested: Set<String> = emptySet(),
        signers: List<String> = listOf("CN=Some Developer,O=Example,C=DE"),
    ): AppFootprint {
        val label = pkg.substringAfterLast('.').replaceFirstChar { it.uppercase() }
        val entry = LauncherEntry(".Main", label, enabled = !hidden, turnedOff = hidden, iconCoverage = if (hidden) null else 0.8)
        return AppFootprint(pkg, label, listOf(entry), startsAtBoot = false, requested, accessibility, signers)
    }

    private fun footprints(vararg apps: AppFootprint) = FakeFootprints(value(apps.toList()))

    private fun inventory(vararg apps: InstalledApp) = FakePackages(value(apps.toList()))

    // SUSP-5001: a hiding app with powerful access

    private fun hidden(
        accessibility: AccessibilityProbe = FakeAccessibility(),
        policy: DevicePolicy = FakePolicy(),
        settings: SystemSettings = FakeSettings(),
    ) = HiddenAppsCheck(footprints(footprint("com.flash.light", hidden = true)), inventory(app("com.flash.light")), accessibility, policy, settings)

    @Test
    fun `a hiding app from a store is a warning until it holds powerful access`() = runTest {
        assertNull(hidden().outcome().escalation)

        val withAccessibility = hidden(accessibility = FakeAccessibility(value(listOf(AppRef("com.flash.light", "Light"))))).outcome()
        assertEquals(Severity.CRITICAL, withAccessibility.escalation)
        assertEquals(
            "has accessibility access; turned its app drawer icon off after it was installed; from an app store",
            withAccessibility.evidence.last().note,
        )

        val admin = AdminApp(AppRef("com.flash.light", "Light"), isDeviceOwner = false, isProfileOwner = false)
        assertEquals(Severity.CRITICAL, hidden(policy = FakePolicy(admins = value(listOf(admin)))).outcome().escalation)

        val listeners = FakeSettings(secure = mapOf(NotificationAccessCheck.ENABLED_NOTIFICATION_LISTENERS to value("com.flash.light/.L")))
        val reader = hidden(settings = listeners).outcome()
        assertEquals(Severity.CRITICAL, reader.escalation)
        assertTrue(reader.evidence.last().note!!.startsWith("can read your notifications;"))
    }

    @Test
    fun `an unreadable access never escalates, and is noted`() = runTest {
        val outcome = hidden(accessibility = FakeAccessibility(unavailable("binder died"))).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertTrue(outcome.evidence.any { it.label == "Access" && it.value == null })
    }

    @Test
    fun `a trusted hiding app with accessibility is listed, not counted`() = runTest {
        val outcome = hidden(accessibility = FakeAccessibility(value(listOf(AppRef("com.flash.light", "Light")))))
            .run(scanContext().copy(trustedApps = setOf("com.flash.light")))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust hide from the app drawer: Light", outcome.summary)
    }

    // SUSP-5004 Apps installed by another app

    private fun installedBy(vararg apps: InstalledApp) = InstalledByAppCheck(FakePackages(value(apps.toList())))

    @Test
    fun `stores, the package installer, installer tools and self-updates don't count`() = runTest {
        val outcome = installedBy(
            app("org.signal", installer = store),
            app("com.example.sideloaded", installer = packageInstaller),
            app(packageInstaller, installer = null, system = true),
            app("com.example.split", installer = "com.aefyr.sai"),
            app("com.aefyr.sai", installer = store),
            app("org.thoughtcrime.securesms", installer = "org.thoughtcrime.securesms"),
            app("com.example.adb", installer = null),
        ).outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals(InstalledByAppCheck.NONE, outcome.summary)
    }

    @Test
    fun `an app installed by another app counts, even when the installer is gone`() = runTest {
        val outcome = installedBy(
            app("com.flash.light", installer = store),
            app("com.bank.payload", installer = "com.flash.light"),
            app("com.other.payload", installer = "com.gone.dropper"),
        ).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("2 apps installed by another app: com.bank.payload and com.other.payload", outcome.summary)
        assertEquals("installed by com.flash.light (com.flash.light)", outcome.evidence[1].note)
        assertEquals("installed by com.gone.dropper, which is no longer installed", outcome.evidence[2].note)
        assertEquals(Trust.COUNTED, outcome.evidence[1].trust)
    }

    @Test
    fun `trusting the installed app or its installer stops counting it`() = runTest {
        val check = installedBy(app("org.unknown.store", installer = store), app("com.example.app", installer = "org.unknown.store"))

        val byInstaller = check.run(scanContext().copy(trustedApps = setOf("org.unknown.store")))
        assertEquals(Status.PASS, byInstaller.status)
        assertEquals(Trust.TRUSTED, byInstaller.evidence.last().trust)

        assertEquals(Status.PASS, check.run(scanContext().copy(trustedApps = setOf("com.example.app"))).status)
    }

    @Test
    fun `an unreadable app list is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, InstalledByAppCheck(FakePackages(unavailable())).status())
    }

    // SUSP-5005 Apps with banking-trojan permissions

    private val trojanPermissions = setOf(RECEIVE_SMS, SYSTEM_ALERT_WINDOW)

    private fun trojan(installer: String? = store, enabled: List<AppRef> = emptyList(), requested: Set<String> = trojanPermissions) =
        TrojanPermissionsCheck(
            footprints(footprint("com.bank.helper", accessibility = true, requested = requested)),
            inventory(app("com.bank.helper", installer)),
            FakeAccessibility(value(enabled)),
        )

    @Test
    fun `accessibility, SMS and overlay together fail`() = runTest {
        val outcome = trojan().outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("1 app with accessibility, SMS and overlay permissions: Helper", outcome.summary)
        assertEquals("accessibility service off; from an app store", outcome.evidence.last().note)
    }

    @Test
    fun `sideloaded, or with its accessibility service on, is critical`() = runTest {
        assertEquals(Severity.CRITICAL, trojan(installer = packageInstaller).outcome().escalation)
        assertEquals(Severity.CRITICAL, trojan(enabled = listOf(AppRef("com.bank.helper", "Helper"))).outcome().escalation)
    }

    @Test
    fun `two of the three are not enough`() = runTest {
        assertEquals(Status.PASS, trojan(requested = setOf(READ_SMS)).status())
        assertEquals(Status.PASS, trojan(requested = setOf(SYSTEM_ALERT_WINDOW)).status())
        val noService = TrojanPermissionsCheck(
            footprints(footprint("com.bank.helper", requested = trojanPermissions)),
            inventory(app("com.bank.helper")),
            FakeAccessibility(),
        )
        assertEquals(Status.PASS, noService.status())
    }

    @Test
    fun `a trusted automation app passes, named`() = runTest {
        val outcome = trojan().run(scanContext().copy(trustedApps = setOf("com.bank.helper")))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust ask for all three: Helper", outcome.summary)
    }

    // SUSP-5006 Apps signed with a debug or test key

    private val debugKey = "C=US,O=Android,CN=Android Debug"
    private val testKey = "1.2.840.113549.1.9.1=#1613616e64726f696440616e64726f69642e636f6d,CN=Android,OU=Android,O=Android," +
        "L=Mountain View,ST=California,C=US"

    @Test
    fun `debug and public test keys are told apart from other keys`() {
        assertEquals(TestKeyAppsCheck.Key.DEBUG, TestKeyAppsCheck.keyOf(listOf(debugKey)))
        assertEquals(TestKeyAppsCheck.Key.TEST, TestKeyAppsCheck.keyOf(listOf(testKey)))
        assertEquals(TestKeyAppsCheck.Key.TEST, TestKeyAppsCheck.keyOf(listOf("CN=Real Dev,O=X,C=US", testKey)))
        assertNull(TestKeyAppsCheck.keyOf(listOf("CN=Signal,OU=Whisper,O=Open Whisper Systems,L=San Francisco,ST=California,C=US")))
        assertNull(TestKeyAppsCheck.keyOf(listOf("CN=Android Debug,O=Android\\, Inc,C=US")))
        assertNull(TestKeyAppsCheck.keyOf(emptyList()))
        assertEquals(mapOf("CN" to "Foo, Inc", "C" to "US"), TestKeyAppsCheck.attributes("CN=Foo\\, Inc,C=US"))
    }

    private fun signed(subject: String, debuggable: Boolean) = TestKeyAppsCheck(
        footprints(footprint("com.mod.app", signers = listOf(subject))),
        inventory(app("com.mod.app", installer = packageInstaller, debuggable = debuggable)),
    )

    @Test
    fun `a developer's debuggable build is a notice, a re-signed release or a test key a warning`() = runTest {
        val devBuild = signed(debugKey, debuggable = true).outcome()
        assertEquals(Status.FAIL, devBuild.status)
        assertNull(devBuild.escalation)
        assertEquals("1 app signed with a debug or test key: App", devBuild.summary)
        assertEquals("Android's debug key; installed from outside an app store", devBuild.evidence.last().note)

        val repackaged = signed(debugKey, debuggable = false).outcome()
        assertEquals(Severity.WARNING, repackaged.escalation)
        assertEquals(
            "Android's debug key, on an app that isn't debuggable; installed from outside an app store",
            repackaged.evidence.last().note,
        )

        assertEquals(Severity.WARNING, signed(testKey, debuggable = true).outcome().escalation)
    }

    @Test
    fun `apps with their own key pass`() = runTest {
        assertEquals(Status.PASS, signed("CN=Some Developer,O=Example,C=DE", debuggable = false).status())
    }

    @Test
    fun `the new checks belong to suspicious apps`() {
        val probes = FakeProbes()
        listOf(
            InstalledByAppCheck(probes.packages),
            TrojanPermissionsCheck(probes.footprints, probes.packages, probes.accessibility),
            TestKeyAppsCheck(probes.footprints, probes.packages),
        ).forEach { assertEquals(Category.SUSPICIOUS_APPS, it.spec.category, it.spec.id) }
    }
}
