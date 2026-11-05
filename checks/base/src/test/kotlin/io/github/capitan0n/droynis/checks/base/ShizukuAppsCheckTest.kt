package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Capabilities
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Apps with Shizuku access (APPS-4016). */
class ShizukuAppsCheckTest {

    private val manager = ShizukuAppsCheck.MANAGER
    private val canta = "org.samo_lego.canta"
    private val appOps = "rikka.appops"
    private val stranger = "org.example.helper"

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private val labels = mapOf(manager to "Shizuku", canta to "Canta", appOps to "App Ops", stranger to "Helper")

    private val inventory = FakePackages(
        value(listOf(app(manager), app(canta), app(appOps, installer = "com.android.vending"), app(stranger, installer = null))),
        labels,
    )

    private fun check(holders: Reading<Map<String, Set<String>>>, packages: PackageInventory = inventory) =
        ShizukuAppsCheck(FakePermissions(holders), packages)

    private fun granted(vararg packages: String) = value(packages.associateWith { setOf(ShizukuAppsCheck.PERMISSION) })

    @Test
    fun `a base check that reads Shizuku's permission`() {
        val spec = check(granted()).spec
        assertEquals(Tier.BASE, spec.requiredTier)
        assertEquals("APPS-4016", spec.id)
        assertEquals("moe.shizuku.manager.permission.API_V23", ShizukuAppsCheck.PERMISSION)
    }

    @Test
    fun `no app with Shizuku access passes, saying whether the Shizuku app is installed`() = runTest {
        val outcome = check(granted()).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app may use Shizuku", outcome.summary)
        assertEquals("Shizuku ($manager)", outcome.evidence.single { it.label == "Shizuku app" }.value)
        assertEquals("none", outcome.evidence.single { it.label == "Shizuku access" }.value)

        val without = check(granted(), FakePackages(value(listOf(app(canta))), labels)).outcome()
        assertEquals("not installed", without.evidence.single { it.label == "Shizuku app" }.value)
    }

    @Test
    fun `apps with Shizuku access fail, a sideloaded one as a warning`() = runTest {
        val store = check(granted(canta, appOps)).outcome()
        assertEquals(Status.FAIL, store.status)
        assertEquals("2 apps may use Shizuku: App Ops and Canta", store.summary)
        assertNull(store.escalation)
        val rows = store.evidence.filter { it.label == "Shizuku access" }
        assertEquals(listOf(appOps, canta), rows.map { it.packageName })
        assertTrue(rows.all { it.trust == Trust.COUNTED })

        val sideloaded = check(granted(canta, stranger)).outcome()
        assertEquals(Severity.WARNING, sideloaded.escalation)
        assertEquals("2 apps may use Shizuku: Canta and Helper; Helper comes from outside an app store", sideloaded.summary)
        assertEquals("installed from outside an app store", sideloaded.evidence.single { it.packageName == stranger }.note)
    }

    @Test
    fun `an app that came with the phone still counts, since someone allowed it`() = runTest {
        val packages = FakePackages(value(listOf(app("com.example.tool", system = true))), mapOf("com.example.tool" to "Tool"))
        val outcome = check(granted("com.example.tool"), packages).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("came with the phone", outcome.evidence.single { it.packageName == "com.example.tool" }.note)
    }

    @Test
    fun `trusted apps are listed but not counted, Droynis's own shell never`() = runTest {
        val context = scanContext().copy(
            trustedApps = setOf(canta),
            capabilities = Capabilities(setOf(Grant.SHIZUKU)),
        )
        val outcome = check(granted(canta)).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only Droynis and apps you trust may use Shizuku: Canta", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.single { it.packageName == canta }.trust)
        assertEquals("this app; not counted", outcome.evidence.single { it.value == "Droynis" }.note)

        val alone = check(granted()).run(context)
        assertEquals("No app other than Droynis may use Shizuku", alone.summary)
    }

    @Test
    fun `permissions that can't be read are never a pass`() = runTest {
        val outcome = check(unavailable("package manager died")).outcome()

        assertEquals(Status.UNKNOWN, outcome.status)
        assertEquals("Could not read which apps may use Shizuku", outcome.summary)
    }
}
