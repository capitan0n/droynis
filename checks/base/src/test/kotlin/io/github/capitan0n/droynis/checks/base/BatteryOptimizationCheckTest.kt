package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Apps that skip battery optimization (APPS-4013). */
class BatteryOptimizationCheckTest {

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private val apps = listOf(
        app("com.google.android.gms", system = true),
        app("org.thoughtcrime.securesms"),
        app("org.example.tracker", installer = null),
        app("org.osmand.plus"),
    )

    private val labels = mapOf(
        "org.thoughtcrime.securesms" to "Signal",
        "org.example.tracker" to "Tracker",
        "org.osmand.plus" to "OsmAnd",
    )

    private fun check(exempt: Reading<Set<String>>, installed: Reading<List<InstalledApp>> = value(apps)) =
        FakeBattery(exempt).let { battery -> battery to BatteryOptimizationCheck(battery, FakePackages(installed, labels)) }

    @Test
    fun `no user app on the allowlist passes, and system apps are never asked about`() = runTest {
        val (battery, check) = check(value(setOf("com.google.android.gms")))
        val outcome = check.outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app you installed skips battery optimization", outcome.summary)
        assertFalse("com.google.android.gms" in battery.asked)
        assertEquals("3", outcome.evidence.single { it.label == "User apps inspected" }.value)
    }

    @Test
    fun `allowlisted user apps are listed for information, a sideloaded one named but not escalated`() = runTest {
        val outcome = check(value(setOf("org.thoughtcrime.securesms", "org.example.tracker"))).second.outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals(
            "2 apps may run in the background without limits: Signal and Tracker; Tracker comes from outside an app store",
            outcome.summary,
        )
        val rows = outcome.evidence.filter { it.label == "Unrestricted battery use" }
        assertEquals(listOf("Signal (org.thoughtcrime.securesms)", "Tracker (org.example.tracker)"), rows.map { it.value })
        assertEquals(listOf("org.thoughtcrime.securesms", "org.example.tracker"), rows.map { it.packageName })
        assertEquals("installed from outside an app store", rows.last().note)
    }

    @Test
    fun `an unreadable allowlist or app list is never a pass`() = runTest {
        assertEquals(Status.UNKNOWN, check(unavailable("binder died")).second.status())
        assertEquals(Status.UNKNOWN, check(value(emptySet()), installed = unavailable()).second.status())
    }

    @Test
    fun `a phone with no user apps passes without asking`() = runTest {
        val (battery, check) = check(value(emptySet()), installed = value(listOf(app("android", system = true))))

        assertEquals(Status.PASS, check.status())
        assertTrue(battery.asked.isEmpty())
    }
}
