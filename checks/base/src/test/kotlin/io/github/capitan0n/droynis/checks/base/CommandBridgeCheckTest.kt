package io.github.capitan0n.droynis.checks.base

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

/** Apps that can run commands through Termux or Tasker (APPS-4019). */
class CommandBridgeCheckTest {

    private val termux = CommandBridgeCheck.TERMUX
    private val termuxApi = "com.termux.api"
    private val tasker = "net.dinglisch.android.taskerm"
    private val automation = "com.example.automation"
    private val stranger = "org.example.helper"

    private val runCommand = CommandBridgeCheck.Bridge.TERMUX.permission
    private val runTasks = CommandBridgeCheck.Bridge.TASKER.permission

    private fun app(pkg: String, uid: Int, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = false, isDebuggable = false, installer = installer, targetSdk = 35, uid = uid)

    private val labels = mapOf(
        termux to "Termux",
        termuxApi to "Termux:API",
        tasker to "Tasker",
        automation to "Automation",
        stranger to "Helper",
    )

    private val inventory = FakePackages(
        value(
            listOf(
                app(termux, 10200),
                // Termux's plugins share its uid.
                app(termuxApi, 10200),
                app(tasker, 10300, installer = "com.android.vending"),
                app(automation, 10400, installer = "com.android.vending"),
                app(stranger, 10500, installer = null),
            ),
        ),
        labels,
    )

    private fun check(holders: Reading<Map<String, Set<String>>>, packages: PackageInventory = inventory) =
        CommandBridgeCheck(FakePermissions(holders), packages)

    @Test
    fun `a base check that names both permissions`() {
        val spec = check(value(emptyMap())).spec
        assertEquals("APPS-4019", spec.id)
        assertEquals(Tier.BASE, spec.requiredTier)
        assertEquals("com.termux.permission.RUN_COMMAND", runCommand)
        assertEquals("net.dinglisch.android.tasker.PERMISSION_RUN_TASKS", runTasks)
    }

    @Test
    fun `no other app with either permission passes, saying which apps are installed`() = runTest {
        // Termux and its plugin hold Termux's own permission; Tasker holds its own.
        val outcome = check(value(mapOf(termux to setOf(runCommand), termuxApi to setOf(runCommand), tasker to setOf(runTasks)))).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app may run commands in Termux or start Tasker tasks", outcome.summary)
        assertEquals("Termux ($termux)", outcome.evidence.single { it.label == "Termux" }.value)
        assertEquals("Tasker ($tasker)", outcome.evidence.single { it.label == "Tasker" }.value)
        assertEquals("none", outcome.evidence.single { it.label == "Apps that may use them" }.value)

        val without = check(value(emptyMap()), FakePackages(value(emptyList()))).outcome()
        assertEquals("not installed", without.evidence.single { it.label == "Termux" }.value)
        assertEquals("not installed", without.evidence.single { it.label == "Tasker" }.value)
    }

    @Test
    fun `an app that may run Termux commands fails, naming what Termux can use`() = runTest {
        val holders = mapOf(
            automation to setOf(runCommand),
            termuxApi to setOf("android.permission.SEND_SMS", "android.permission.CAMERA"),
        )
        val outcome = check(value(holders)).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app may run commands in Termux: Automation", outcome.summary)
        assertNull(outcome.escalation)
        val row = outcome.evidence.single { it.packageName == automation && it.label == "Termux commands" }
        assertEquals(Trust.COUNTED, row.trust)
        assertEquals("send SMS, camera", outcome.evidence.single { it.label == "What Termux commands can use" }.value)
    }

    @Test
    fun `apps for both bridges are named together, a sideloaded one as a warning`() = runTest {
        val outcome = check(value(mapOf(automation to setOf(runCommand, runTasks), stranger to setOf(runTasks)))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(
            "2 apps may run commands in Termux or start Tasker tasks: Automation and Helper; Helper comes from outside an app store",
            outcome.summary,
        )
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals("Termux commands and Tasker tasks", outcome.evidence.single { it.packageName == automation && it.trust != null }.label)
        assertEquals("Tasker tasks", outcome.evidence.single { it.packageName == stranger }.label)
    }

    @Test
    fun `an app that only borrows Termux's name still counts`() = runTest {
        val packages = FakePackages(value(listOf(app(termux, 10200), app("com.termux.fake", 10600, installer = null))))
        val outcome = check(value(mapOf("com.termux.fake" to setOf(runCommand))), packages).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
    }

    @Test
    fun `trusted apps are listed but not counted`() = runTest {
        val context = scanContext().copy(trustedApps = setOf(automation))
        val outcome = check(value(mapOf(automation to setOf(runTasks)))).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust may start Tasker tasks: Automation", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.single { it.packageName == automation && it.trust != null }.trust)
    }

    @Test
    fun `Termux's own permissions are left out when nothing sensitive is granted`() = runTest {
        val outcome = check(value(mapOf(automation to setOf(runCommand)))).outcome()

        assertFalse(outcome.evidence.any { it.label == "What Termux commands can use" })
        assertTrue(outcome.evidence.any { it.label == "Termux commands" })
    }

    @Test
    fun `permissions that can't be read are never a pass`() = runTest {
        val outcome = check(unavailable("package manager died")).outcome()

        assertEquals(Status.UNKNOWN, outcome.status)
    }
}
