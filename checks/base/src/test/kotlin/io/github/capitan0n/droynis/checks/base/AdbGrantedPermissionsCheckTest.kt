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
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Apps with system permissions granted over adb (APPS-4020). */
class AdbGrantedPermissionsCheckTest {

    private val writeSecure = "android.permission.WRITE_SECURE_SETTINGS"
    private val readLogs = "android.permission.READ_LOGS"
    private val dump = "android.permission.DUMP"

    private val tasker = "net.dinglisch.android.taskerm"
    private val logcat = "com.example.logcat"
    private val settingsProvider = "com.android.providers.settings"

    private fun app(pkg: String, system: Boolean = false, installer: String? = "com.android.vending") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private val inventory = FakePackages(
        value(listOf(app(tasker), app(logcat, installer = null), app(settingsProvider, system = true))),
        mapOf(tasker to "Tasker", logcat to "Logcat Reader", settingsProvider to "Settings Storage"),
    )

    private fun check(holders: Reading<Map<String, Set<String>>>) = AdbGrantedPermissionsCheck(FakePermissions(holders), inventory)

    @Test
    fun `a base warning`() {
        val spec = check(value(emptyMap())).spec
        assertEquals("APPS-4020", spec.id)
        assertEquals(Tier.BASE, spec.requiredTier)
        assertEquals(Severity.WARNING, spec.severity)
        assertEquals(
            listOf(writeSecure, readLogs, dump, "android.permission.INTERACT_ACROSS_USERS"),
            AdbGrantedPermissionsCheck.Power.entries.map { it.permission },
        )
    }

    @Test
    fun `apps that came with the phone hold them by privilege and are only counted`() = runTest {
        val outcome = check(value(mapOf(settingsProvider to setOf(writeSecure, dump)))).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app you installed holds a system permission granted over adb", outcome.summary)
        assertEquals("1", outcome.evidence.single { it.label == "Apps that came with the phone and hold them" }.value)
        assertFalse(outcome.evidence.any { it.packageName == settingsProvider })
    }

    @Test
    fun `installed apps holding them fail, each with what it may do`() = runTest {
        // Other permissions the probe returns are ignored.
        val holders = mapOf(
            tasker to setOf(writeSecure, "android.permission.CAMERA"),
            logcat to setOf(readLogs, dump),
        )
        val outcome = check(value(holders)).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 apps hold system permissions granted over adb: Logcat Reader and Tasker", outcome.summary)
        assertNull(outcome.escalation)
        val tasks = outcome.evidence.single { it.packageName == tasker }
        assertEquals("WRITE_SECURE_SETTINGS: change secure settings; from an app store", tasks.note)
        assertEquals(Trust.COUNTED, tasks.trust)
        assertEquals(
            "READ_LOGS: read the system log, DUMP: read system service dumps; installed from outside an app store",
            outcome.evidence.single { it.packageName == logcat }.note,
        )
    }

    @Test
    fun `trusted apps pass, and Droynis's own DUMP grant is listed but never counted`() = runTest {
        val context = scanContext().copy(trustedApps = setOf(tasker), capabilities = Capabilities(setOf(Grant.DUMP)))
        val outcome = check(value(mapOf(tasker to setOf(writeSecure)))).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps that came with the phone and apps you trust hold system permissions granted over adb: Tasker", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.single { it.packageName == tasker }.trust)
        assertEquals("DUMP, for the ADB tier; this app; not counted", outcome.evidence.single { it.value == "Droynis" }.note)
    }

    @Test
    fun `the Shizuku app is listed but never counted`() = runTest {
        val packages = FakePackages(value(listOf(app(ShizukuAppsCheck.MANAGER, installer = "org.fdroid.fdroid"))), mapOf(ShizukuAppsCheck.MANAGER to "Shizuku"))
        val outcome = AdbGrantedPermissionsCheck(FakePermissions(value(mapOf(ShizukuAppsCheck.MANAGER to setOf(writeSecure)))), packages).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertTrue("Listed separately: Shizuku" in outcome.summary)
        val row = outcome.evidence.single { it.packageName == ShizukuAppsCheck.MANAGER }
        assertEquals(Trust.NOT_COUNTED, row.trust)
        assertEquals("WRITE_SECURE_SETTINGS; Shizuku itself, which has adb's rights anyway (APPS-4016); not counted", row.note)
    }

    @Test
    fun `permissions that can't be read are never a pass`() = runTest {
        assertEquals(Status.UNKNOWN, check(unavailable("package manager died")).status())
    }

    @Test
    fun `an app list that can't be read is unknown, never a fail over system apps`() = runTest {
        val packages = FakePackages(unavailable("package manager died"), mapOf(settingsProvider to "Settings Storage"))
        val outcome = AdbGrantedPermissionsCheck(FakePermissions(value(mapOf(settingsProvider to setOf(writeSecure)))), packages).outcome()

        assertEquals(Status.UNKNOWN, outcome.status)
        assertFalse(outcome.evidence.any { it.packageName == settingsProvider })
    }
}
