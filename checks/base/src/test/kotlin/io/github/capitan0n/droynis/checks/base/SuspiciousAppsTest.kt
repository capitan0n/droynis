package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.FOREGROUND_SERVICE
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.SYSTEM_ALERT_WINDOW
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Hidden apps (SUSP-5001), set up to run in the background (SUSP-5002) and showing screens (SUSP-5003). */
class SuspiciousAppsTest {

    private val store = "org.fdroid.fdroid"
    private val packageInstaller = "com.google.android.packageinstaller"

    private fun app(pkg: String, installer: String? = store, system: Boolean = false, enabled: Boolean = true) =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35, isEnabled = enabled)

    private fun entry(
        label: String = "App",
        enabled: Boolean = true,
        turnedOff: Boolean = false,
        coverage: Double? = 0.8,
        className: String = ".Main",
    ) = LauncherEntry(className, label, enabled, turnedOff, coverage)

    private fun footprint(
        pkg: String,
        label: String = pkg.substringAfterLast('.').replaceFirstChar { it.uppercase() },
        entries: List<LauncherEntry> = listOf(entry(label)),
        boot: Boolean = false,
        vararg requested: String,
    ) = AppFootprint(pkg, label, entries, startsAtBoot = boot, requested = requested.toSet())

    private fun inventory(vararg apps: InstalledApp) = FakePackages(value(apps.toList()))

    private fun footprints(vararg apps: AppFootprint) = FakeFootprints(value(apps.toList()))

    /** SUSP-5001 with no app holding accessibility, device admin or notification access. */
    private fun hiddenApps(footprints: AppFootprintProbe, packages: PackageInventory) =
        HiddenAppsCheck(footprints, packages, FakeAccessibility(), FakePolicy(), FakeSettings())

    // Invisible text

    @Test
    fun `labels made only of spaces, format characters or blank letters are invisible`() {
        listOf(
            "", "   ", " ", "​", "​‌‍", "⁠", "﻿", "­",
            "ㅤ", "ᅟᅠ", "ﾠ", "⠀", "⠀ ‍", "́", "͏", "️", "　",
        ).forEach { assertTrue(isInvisibleText(it), "\"$it\" (${it.map { c -> "U+%04X".format(c.code) }}) should be invisible") }
    }

    @Test
    fun `labels with anything that draws are visible`() {
        listOf("Signal", " a ", "​x", "👀", "क", "اپ", ".", "é").forEach {
            assertFalse(isInvisibleText(it), "\"$it\" should be visible")
        }
    }

    // Signs

    @Test
    fun `a launcher turned off at runtime or in the manifest hides the app`() {
        val turnedOff = footprint("a.b", entries = listOf(entry(enabled = false, turnedOff = true)))
        assertEquals(listOf(HidingSign.ICON_TURNED_OFF), AppPresence.signs(turnedOff))

        val manifest = footprint("a.b", entries = listOf(entry(enabled = false)))
        assertEquals(listOf(HidingSign.ICON_DISABLED), AppPresence.signs(manifest))
    }

    @Test
    fun `one visible entry is enough, even next to a turned-off alias`() {
        val swapped = footprint(
            "a.b",
            entries = listOf(entry(enabled = false, turnedOff = true, className = ".Old"), entry("App", className = ".New")),
        )
        assertEquals(emptyList(), AppPresence.signs(swapped))
    }

    @Test
    fun `a blank name or a transparent icon on an enabled entry hides the app`() {
        assertEquals(listOf(HidingSign.BLANK_NAME), AppPresence.signs(footprint("a.b", label = "ㅤ")))
        assertEquals(
            listOf(HidingSign.BLANK_NAME),
            AppPresence.signs(AppFootprint("a.b", "Visible", listOf(entry("​")), startsAtBoot = false)),
        )
        assertEquals(listOf(HidingSign.INVISIBLE_ICON), AppPresence.signs(footprint("a.b", entries = listOf(entry(coverage = 0.0)))))
        assertEquals(
            listOf(HidingSign.BLANK_NAME, HidingSign.INVISIBLE_ICON),
            AppPresence.signs(footprint("a.b", label = " ", entries = listOf(entry(" ", coverage = 0.01)))),
        )
    }

    @Test
    fun `an icon that wasn't drawn, or a disabled entry's look, is not judged`() {
        assertEquals(emptyList(), AppPresence.signs(footprint("a.b", entries = listOf(entry(coverage = null)))))
        // A blank label on a disabled alias is never shown.
        val alias = listOf(entry("App"), entry("", enabled = false, coverage = null, className = ".Alias"))
        assertEquals(emptyList(), AppPresence.signs(footprint("a.b", entries = alias)))
    }

    @Test
    fun `no launcher entry at all is out of sight but not hiding`() {
        val addOn = AppPresence.sightings(listOf(footprint("a.plugin", entries = emptyList())), mapOf("a.plugin" to app("a.plugin")))
            .single()
        assertFalse(addOn.hiding)
        assertTrue(addOn.outOfSight)
        assertEquals(Severity.NOTICE, addOn.concern)
        assertFalse(addOn.counted)
    }

    @Test
    fun `hiding and coming from outside an app store each raise the concern`() {
        fun concern(entries: List<LauncherEntry>, installer: String?) =
            AppPresence.sightings(listOf(footprint("a.b", entries = entries)), mapOf("a.b" to app("a.b", installer))).single().concern

        val hidden = listOf(entry(enabled = false, turnedOff = true))
        assertEquals(Severity.CRITICAL, concern(hidden, packageInstaller))
        assertEquals(Severity.CRITICAL, concern(hidden, null))
        assertEquals(Severity.WARNING, concern(hidden, store))
        assertEquals(Severity.WARNING, concern(emptyList(), packageInstaller))
        assertEquals(Severity.NOTICE, concern(emptyList(), store))
    }

    @Test
    fun `system and disabled apps are left out even if the probe lists them`() {
        val sightings = AppPresence.sightings(
            listOf(footprint("sys.app", entries = emptyList()), footprint("off.app", entries = emptyList()), footprint("new.app")),
            mapOf("sys.app" to app("sys.app", system = true), "off.app" to app("off.app", enabled = false)),
        )
        assertEquals(listOf("new.app"), sightings.map { it.packageName })
        assertEquals(AppOrigin.UNKNOWN, sightings.single().origin)
    }

    // SUSP-5001 Apps hiding from the app drawer

    @Test
    fun `spec belongs to the suspicious apps category`() {
        val spec = hiddenApps(FakeFootprints(), FakePackages()).spec
        assertEquals("SUSP-5001", spec.id)
        assertEquals(Category.SUSPICIOUS_APPS, spec.category)
        assertEquals(Severity.WARNING, spec.severity)
    }

    @Test
    fun `apps with a visible icon, or none at all, pass`() = runTest {
        val outcome = hiddenApps(
            footprints(footprint("org.signal"), footprint("a.plugin", entries = emptyList())),
            inventory(app("org.signal"), app("a.plugin")),
        ).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No installed app hides from the app drawer", outcome.summary)
        assertEquals("2", outcome.evidence.single().value)
    }

    @Test
    fun `a hiding app from a store is a warning, a sideloaded one critical`() = runTest {
        val fromStore = hiddenApps(
            footprints(footprint("com.flash.light", entries = listOf(entry(enabled = false, turnedOff = true)))),
            inventory(app("com.flash.light")),
        ).outcome()
        assertEquals(Status.FAIL, fromStore.status)
        assertNull(fromStore.escalation)
        assertEquals("1 app hiding from the app drawer: Light", fromStore.summary)
        val hiding = fromStore.evidence.last()
        assertEquals("Light (com.flash.light)", hiding.value)
        assertEquals("com.flash.light", hiding.packageName)
        assertEquals("turned its app drawer icon off after it was installed; from an app store", hiding.note)

        val sideloaded = hiddenApps(
            footprints(footprint("x.ads", label = "ㅤ", entries = listOf(entry("ㅤ", coverage = 0.0)))),
            inventory(app("x.ads", installer = packageInstaller)),
        ).outcome()
        assertEquals(Severity.CRITICAL, sideloaded.escalation)
        // A blank name is shown by its package name.
        assertEquals("1 app hiding from the app drawer: x.ads", sideloaded.summary)
        assertEquals(
            "has a blank name; has a transparent icon; installed from outside an app store",
            sideloaded.evidence.last().note,
        )
    }

    @Test
    fun `a hiding app the user trusts is listed but not counted`() = runTest {
        val check = hiddenApps(
            footprints(
                footprint("org.prey", entries = listOf(entry(enabled = false, turnedOff = true))),
                footprint("x.ads", entries = listOf(entry(coverage = 0.0))),
            ),
            inventory(app("org.prey", installer = packageInstaller), app("x.ads", installer = packageInstaller)),
        )

        val both = check.run(scanContext().copy(trustedApps = setOf("org.prey")))
        assertEquals(Status.FAIL, both.status)
        assertEquals("1 app hiding from the app drawer: Ads", both.summary)
        assertEquals(listOf(Trust.TRUSTED, Trust.COUNTED), both.evidence.drop(1).map { it.trust })
        assertTrue(both.evidence[1].note!!.endsWith("; $TRUSTED_NOTE"), both.evidence[1].note)

        val onlyTrusted = check.run(scanContext().copy(trustedApps = setOf("org.prey", "x.ads")))
        assertEquals(Status.PASS, onlyTrusted.status)
        assertEquals("Only apps you trust hide from the app drawer: Prey and Ads", onlyTrusted.summary)
    }

    @Test
    fun `add-ons that are never counted say so in their evidence`() = runTest {
        val outcome = HiddenAutostartCheck(
            footprints(footprint("a.plugin", entries = emptyList(), boot = true)),
            inventory(app("a.plugin")),
            FakeBattery(),
        ).outcome()
        assertEquals(Trust.NOT_COUNTED, outcome.evidence.last().trust)
    }

    @Test
    fun `a trusted hidden app running in the background passes, named`() = runTest {
        val outcome = HiddenAutostartCheck(
            footprints(footprint("x.svc", entries = emptyList(), boot = true)),
            inventory(app("x.svc", installer = null)),
            FakeBattery(),
        ).run(scanContext().copy(trustedApps = setOf("x.svc")))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only hidden apps you trust are set up to run in the background: Svc", outcome.summary)
        assertNull(outcome.escalation)
    }

    @Test
    fun `an unreadable app list is never a pass`() = runTest {
        assertEquals(Status.UNKNOWN, hiddenApps(FakeFootprints(unavailable("binder died")), inventory()).status())
        assertEquals(Status.UNSUPPORTED, hiddenApps(FakeFootprints(unsupported()), inventory()).status())
        assertEquals(
            Status.UNKNOWN,
            hiddenApps(footprints(footprint("a.b")), FakePackages(unavailable())).status(),
        )
    }

    // SUSP-5002 Hidden apps set up to run in the background

    private fun autostart(vararg apps: Pair<AppFootprint, InstalledApp>, battery: FakeBattery = FakeBattery()) =
        HiddenAutostartCheck(
            footprints(*apps.map { it.first }.toTypedArray()),
            inventory(*apps.map { it.second }.toTypedArray()),
            battery,
        )

    @Test
    fun `visible apps that start at boot are none of this check's business`() = runTest {
        val battery = FakeBattery()
        val outcome = autostart(footprint("org.signal", boot = true, requested = arrayOf(FOREGROUND_SERVICE)) to app("org.signal"), battery = battery)
            .outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals("No hidden app is set up to run in the background", outcome.summary)
        assertEquals(emptyList(), battery.asked)
    }

    @Test
    fun `an add-on from an app store is listed, not counted`() = runTest {
        val outcome = autostart(footprint("a.plugin", entries = emptyList(), boot = true) to app("a.plugin")).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals(
            "No hidden app is set up to run in the background (1 add-on without an icon of its own listed, not counted)",
            outcome.summary,
        )
        assertEquals("starts when the phone starts; no app drawer icon; from an app store; not counted", outcome.evidence.last().note)
    }

    @Test
    fun `a sideloaded app without an icon is a warning, one that hides critical`() = runTest {
        val noIcon = autostart(
            footprint("x.svc", entries = emptyList(), requested = arrayOf(FOREGROUND_SERVICE)) to app("x.svc", installer = null),
        ).outcome()
        assertEquals(Status.FAIL, noIcon.status)
        assertNull(noIcon.escalation)
        assertEquals("1 hidden app set up to run in the background: Svc", noIcon.summary)

        val battery = FakeBattery(value(setOf("x.ads")))
        val hiding = autostart(
            footprint(
                "x.ads",
                entries = listOf(entry(enabled = false, turnedOff = true)),
                boot = true,
                requested = arrayOf(SYSTEM_ALERT_WINDOW, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS),
            ) to app("x.ads", installer = packageInstaller),
            footprint("a.plugin", entries = emptyList(), boot = true) to app("a.plugin"),
            battery = battery,
        ).outcome()
        assertEquals(Severity.CRITICAL, hiding.escalation)
        assertEquals("1 hidden app set up to run in the background: Ads", hiding.summary)
        assertEquals(listOf("x.ads", "a.plugin"), battery.asked)
        // Counted apps come first; Android already lets this one skip battery limits.
        assertEquals(
            "starts when the phone starts, asks to draw over other apps, skips battery limits; " +
                "turned its app drawer icon off after it was installed; installed from outside an app store",
            hiding.evidence[1].note,
        )
    }

    @Test
    fun `unreadable battery limits are noted but don't hide the finding`() = runTest {
        val outcome = autostart(
            footprint("x.svc", entries = emptyList(), requested = arrayOf(REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)) to app("x.svc", null),
            battery = FakeBattery(unavailable("binder died")),
        ).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertTrue(outcome.evidence.any { it.label == "Battery limits" && it.value == null })
        assertTrue(outcome.evidence.last().note!!.startsWith("asks to skip battery limits;"))
    }

    // SUSP-5003 Hidden apps showing screens

    private val now: Instant = scanContext().startedAt.toInstant()

    private fun screens(
        usage: FakeUsageHistory,
        vararg apps: Pair<AppFootprint, InstalledApp>,
    ) = HiddenScreensCheck(
        footprints(*apps.map { it.first }.toTypedArray()),
        inventory(*apps.map { it.second }.toTypedArray()),
        usage,
    )

    @Test
    fun `without usage access the check is not available`() = runTest {
        val outcome = screens(FakeUsageHistory(access = value(false))).outcome()
        assertEquals(Status.UNSUPPORTED, outcome.status)
        assertTrue(outcome.summary.startsWith("Needs usage access"), outcome.summary)
        assertEquals("off", outcome.evidence.single().value)

        assertEquals(Status.UNKNOWN, screens(FakeUsageHistory(access = unavailable())).status())
    }

    @Test
    fun `with nothing out of sight the history isn't read`() = runTest {
        val usage = FakeUsageHistory(access = value(true))
        val outcome = screens(usage, footprint("org.signal") to app("org.signal")).outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Every app you installed has a visible app drawer icon", outcome.summary)
        assertEquals(emptyList(), usage.asked)
    }

    @Test
    fun `a hidden app that showed a screen fails, asked only about hidden apps for 7 days`() = runTest {
        val usage = FakeUsageHistory(
            access = value(true),
            screens = value(
                mapOf(
                    "x.ads" to ScreenUse("x.ads", 14, now.minusSeconds(3 * 3600)),
                    "a.plugin" to ScreenUse("a.plugin", 1, now.minusSeconds(600)),
                    "org.signal" to ScreenUse("org.signal", 50, now),
                ),
            ),
        )
        val outcome = screens(
            usage,
            footprint("x.ads", entries = listOf(entry(coverage = 0.0))) to app("x.ads", installer = packageInstaller),
            footprint("a.plugin", entries = emptyList()) to app("a.plugin"),
            footprint("org.signal") to app("org.signal"),
        ).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.CRITICAL, outcome.escalation)
        assertEquals("1 hidden app showed screens of its own: Ads", outcome.summary)
        val (packages, since) = usage.asked.single()
        assertEquals(setOf("x.ads", "a.plugin"), packages)
        assertEquals(now.minusSeconds(7 * 24 * 3600), since)
        val ads = outcome.evidence.single { it.packageName == "x.ads" }
        assertEquals(
            "showed screens 14 times, most recently 3 hours ago; has a transparent icon; installed from outside an app store",
            ads.note,
        )
        assertEquals(
            "showed a screen once, within the last hour; no app drawer icon; from an app store; not counted",
            outcome.evidence.single { it.packageName == "a.plugin" }.note,
        )
    }

    @Test
    fun `only add-ons from a store showing screens pass, listed`() = runTest {
        val usage = FakeUsageHistory(value(true), value(mapOf("a.plugin" to ScreenUse("a.plugin", 2, now))))
        val outcome = screens(usage, footprint("a.plugin", entries = emptyList()) to app("a.plugin")).outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals(
            "No hidden app showed a screen of its own in the last 7 days (1 add-on without an icon of its own listed, not counted)",
            outcome.summary,
        )
    }

    @Test
    fun `an unreadable usage history is never a pass`() = runTest {
        val usage = FakeUsageHistory(value(true), unavailable("SecurityException"))
        val outcome = screens(usage, footprint("x.ads", entries = emptyList()) to app("x.ads", null)).outcome()
        assertEquals(Status.UNKNOWN, outcome.status)
    }

    @Test
    fun `the registry runs the base suspicious apps checks in id order`() {
        val ids = baseChecks(FakeProbes()).filter { it.spec.category == Category.SUSPICIOUS_APPS }.map { it.spec.id }
        assertEquals((5001..5007).map { "SUSP-$it" }, ids)
    }
}
