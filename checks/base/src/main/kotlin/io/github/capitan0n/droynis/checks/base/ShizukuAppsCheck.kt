package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps that may use Shizuku, read from a runtime permission. The Shizuku app defines
 * [PERMISSION] as a dangerous permission, and the Shizuku library adds it to every client's
 * manifest. When the user taps Allow, or turns an app on in Shizuku's list, Shizuku's server grants
 * that app the permission, and on each start it reads its own list back from it (`ShizukuService`
 * and `ShizukuConfigManager`, Shizuku 13). So the granted flag is the stored answer, and reading it
 * needs no privilege. Not seen: "Allow this time", which lasts only while that app runs, and Sui,
 * the root-only variant, which keeps its own list and defines no permission.
 */
class ShizukuAppsCheck(
    private val permissions: PermissionProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4016",
        category = Category.APPS,
        title = "Apps with Shizuku access",
        severity = Severity.NOTICE,
        explanation = "Shizuku gives the apps you allow the rights of adb, or of root when Shizuku runs with " +
            "root. Such an app can install apps and grant them permissions, read the system log, change " +
            "hidden settings, take screenshots and tap the screen for you, without asking again. Allow only " +
            "apps you trust; one installed from outside an app store is a warning. Sui, the variant for " +
            "rooted phones, keeps its own list, which Droynis can't read.",
        remediation = Remediation(
            text = "Open Shizuku, tap Application management (\"Authorized … applications\") and turn off the " +
                "apps you no longer use or don't fully trust. Settings › Apps › the app › Permissions › Shizuku " +
                "› Don't allow does the same.",
        ),
        timeout = 15.seconds,
        failsWhen = "an app other than Droynis may use Shizuku (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val granted = permissions.holders(setOf(PERMISSION))
        if (granted !is Reading.Value) {
            return Outcome.unknown("Could not read which apps may use Shizuku", listOf(granted.toEvidence("Permissions")))
        }
        val installed = packages.installedApps()
        val inventory = (installed as? Reading.Value)?.value?.associateBy { it.packageName }
        val all = granted.value.keys
            .map { Holder(AppRef(it, packages.label(it)), originOf(it, inventory)) }
            .sortedBy { it.app.label.lowercase() }
        // Every holder was allowed by someone, whatever its origin, so all of them count.
        val (trusted, counted) = context.splitTrusted(all) { it.app.packageName }
        // Droynis is left out of the holders; its own Shizuku shell is what the Shizuku tier uses.
        val ownShell = Grant.SHIZUKU in context.capabilities.grants

        val evidence = buildList {
            add(shizukuApp(installed, inventory))
            all.forEach { add(it.evidence("Shizuku access", granted.source, trusted = it in trusted)) }
            if (all.isEmpty()) add(Evidence("Shizuku access", "none", granted.source))
            if (ownShell) add(Evidence("Shizuku access", "Droynis", OWN_SHELL, note = "this app; not counted"))
        }
        if (counted.isEmpty() && trusted.isNotEmpty()) {
            val others = "Droynis".takeIf { ownShell }
            return Outcome.pass(onlyTrusted("may use Shizuku", trusted.labels(), others = others), evidence)
        }
        if (counted.isEmpty()) {
            return Outcome.pass(if (ownShell) "No app other than Droynis may use Shizuku" else "No app may use Shizuku", evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} may use Shizuku: ${counted.labels().joinNames()}" + sideloadedSuffix(counted),
            evidence,
            escalation = sideloadedEscalation(counted),
        )
    }

    /** Whether the Shizuku app itself is installed, as context: without it no app holds the permission. */
    private fun shizukuApp(installed: Reading<List<InstalledApp>>, inventory: Map<String, InstalledApp>?): Evidence = when {
        inventory == null -> installed.toEvidence("Shizuku app")
        MANAGER in inventory -> Evidence("Shizuku app", "${packages.label(MANAGER)} ($MANAGER)", installed.source, packageName = MANAGER)
        else -> Evidence("Shizuku app", "not installed", installed.source)
    }

    companion object {
        /** Defined by the Shizuku app (`ServerConstants.PERMISSION`); every Shizuku client requests it. */
        const val PERMISSION = "moe.shizuku.manager.permission.API_V23"

        /** The Shizuku app (`ServerConstants.MANAGER_APPLICATION_ID`). */
        const val MANAGER = "moe.shizuku.privileged.api"

        /** Where "Droynis uses Shizuku" comes from: its own shell being connected for this scan. */
        private val OWN_SHELL = Source("Droynis' Shizuku shell", Grant.SHIZUKU)
    }
}
