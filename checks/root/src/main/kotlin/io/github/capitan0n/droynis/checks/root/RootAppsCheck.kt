package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/** One row of Magisk's `policies` table. */
data class SuPolicy(val uid: Int, val policy: Int, val until: Long) {
    /** Allowed, or allowed with restrictions, and not expired at [nowSeconds]. */
    fun grantsRoot(nowSeconds: Long): Boolean = policy in ROOT_POLICIES && (until == 0L || until > nowSeconds)

    companion object {
        /** Magisk's `SuPolicy`: Query 0, Deny 1, Allow 2, Restrict 3 (root with a limited context). */
        val ROOT_POLICIES = setOf(2, 3)
    }
}

/** Reads `magisk --sqlite` output: one `column=value|column=value` line per row. */
object MagiskPolicies {

    private val ROW = Regex("""uid=(-?\d+)\|policy=(\d+)\|until=(\d+)""")

    /** Null when any line is in another shape: a format change must never hide a grant. */
    fun parse(text: String): List<SuPolicy>? = text.lines().map { it.trim() }.filter { it.isNotEmpty() }.map { line ->
        val match = ROW.matchEntire(line) ?: return null
        val (uid, policy, until) = match.destructured
        SuPolicy(uid.toIntOrNull() ?: return null, policy.toIntOrNull() ?: return null, until.toLongOrNull() ?: return null)
    }
}

class RootAppsCheck(
    private val root: RootShellProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4301",
        category = Category.APPS,
        title = "Apps with root access",
        severity = Severity.WARNING,
        explanation = "An app with root can read every other app's data, change the system and hide " +
            "what it does: Android's app sandbox no longer limits it. Grant root only to apps you trust " +
            "completely, and take it back from apps you no longer use. Droynis reads Magisk's list; " +
            "KernelSU and APatch keep theirs in formats it can't read yet.",
        remediation = Remediation(
            text = "Open your root manager's Superuser screen and revoke root from apps you don't use " +
                "or don't fully trust. Revoking adb shell's root means a computer with adb gets no root.",
        ),
        requires = setOf(Grant.ROOT),
        // Root reads share one shell, so a check may wait for others.
        timeout = 15.seconds,
        failsWhen = "an app other than Droynis may get root",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val manager = root.manager()
        val managerEvidence = manager.toEvidence("Root manager") { it.label }
        when {
            manager !is Reading.Value -> return Outcome.unknown("The root manager could not be identified", listOf(managerEvidence))
            manager.value != RootManager.MAGISK -> return Outcome.unsupported(
                "Droynis reads the root list of Magisk only; this phone uses ${manager.value.label}",
                listOf(managerEvidence),
            )
        }

        val table = root.magiskPolicies()
        val text = when (table) {
            is Reading.Value -> table.value
            else -> return Outcome.unknown("Magisk's root list could not be read", listOf(managerEvidence, table.toEvidence("Policies")))
        }
        val policies = MagiskPolicies.parse(text) ?: return Outcome.unknown(
            "Magisk's root list is in a format Droynis doesn't recognize",
            listOf(managerEvidence, Evidence("Policies", null, table.source, note = text.lineSequence().firstOrNull()?.take(80))),
        )
        val now = context.startedAt.toEpochSecond()
        val granted = policies.filter { it.grantsRoot(now) }

        val installed = (packages.installedApps() as? Reading.Value)?.value.orEmpty()
        val holders = granted.map { policy -> policy to appsFor(policy.uid, installed) }
        val ownUid = context.appUid
        val own = holders.filter { (policy, _) -> ownUid != null && sameApp(policy.uid, ownUid) }
        val others = holders - own.toSet()

        val evidence = buildList {
            add(managerEvidence)
            add(Evidence("Root grants", count(granted.size, "uid"), table.source))
            others.forEach { (policy, apps) -> add(Evidence("Root access", describe(policy.uid, apps), table.source, note = note(policy))) }
            own.forEach { (policy, _) -> add(Evidence("Root access", "Droynis", table.source, note = "this app; not counted" + (note(policy)?.let { ", $it" } ?: ""))) }
        }
        if (others.isEmpty()) {
            return Outcome.pass(if (own.isEmpty()) "No app has root access" else "Only Droynis has root access", evidence)
        }
        val names = others.map { (policy, apps) -> describe(policy.uid, apps, withPackage = false) }
        return Outcome.fail("${count(names.size, "app")} can get root: ${names.joinNames()}", evidence)
    }

    private fun appsFor(uid: Int, installed: List<InstalledApp>): List<String> =
        installed.filter { app -> app.uid?.let { sameApp(uid, it) } == true }.map { it.packageName }

    /** Magisk stores a full uid, or just the app id when one owner manages every user. */
    private fun sameApp(policyUid: Int, appUid: Int): Boolean =
        policyUid == appUid || (policyUid < PER_USER_RANGE && appUid % PER_USER_RANGE == policyUid)

    private fun describe(uid: Int, apps: List<String>, withPackage: Boolean = true): String = when {
        // The shell uid is adb's, whatever label its package has.
        uid % PER_USER_RANGE == SHELL_UID -> "adb shell"
        apps.isNotEmpty() -> apps.joinToString { pkg -> if (withPackage) "${packages.label(pkg)} ($pkg)" else packages.label(pkg) }
        else -> "uid $uid"
    }

    private fun note(policy: SuPolicy): String? = listOfNotNull(
        "restricted root".takeIf { policy.policy == RESTRICT },
        "until a set time".takeIf { policy.until != 0L },
    ).joinToString(", ").ifEmpty { null }

    private companion object {
        const val PER_USER_RANGE = 100_000
        const val SHELL_UID = 2000
        const val RESTRICT = 3
    }
}
