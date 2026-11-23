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
import io.github.capitan0n.droynis.core.Trust
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps you installed that hold a system permission of the `development` protection level. Android
 * grants those to apps outside the system image only through `pm grant`, so from adb, a Shizuku
 * client or root. The granted flag reads without any privilege; Settings never shows these
 * permissions. Apps that came with the phone hold some of them by privilege and are only counted.
 * The Shizuku app may grant itself WRITE_SECURE_SETTINGS (to start on boot); it already has adb's
 * rights, which APPS-4016 covers, so it is listed but not counted.
 * PACKAGE_USAGE_STATS is development-level too, but APPS-4105 covers it through its app-op.
 */
class AdbGrantedPermissionsCheck(
    private val permissions: PermissionProbe,
    private val packages: PackageInventory,
) : Check {

    /** The permissions this check looks for, with what each lets an app do. */
    enum class Power(val permission: String, val does: String) {
        WRITE_SECURE_SETTINGS("android.permission.WRITE_SECURE_SETTINGS", "change secure settings"),
        READ_LOGS("android.permission.READ_LOGS", "read the system log"),
        DUMP("android.permission.DUMP", "read system service dumps"),
        INTERACT_ACROSS_USERS("android.permission.INTERACT_ACROSS_USERS", "reach other users and profiles"),
        ;

        val shortName: String get() = permission.substringAfterLast('.')
    }

    override val spec = CheckSpec(
        id = "APPS-4020",
        category = Category.APPS,
        title = "Apps with system permissions granted over adb",
        severity = Severity.WARNING,
        explanation = "Some permissions are meant for the system only: changing secure settings, reading the " +
            "system log, where every app's messages end up, reading the dumps of system services, and reaching " +
            "other users of the phone. An app you install gets them only when someone grants them with pm " +
            "grant, from a computer over adb, through Shizuku or with root, and Settings never shows them. " +
            "With WRITE_SECURE_SETTINGS an app can turn on an accessibility service, USB debugging or another " +
            "keyboard without asking you. Automation apps such as Tasker ask for this on purpose; stalkerware " +
            "is set up the same way. Keep these only for apps you set up yourself and trust.",
        remediation = Remediation(
            text = "Uninstall apps you don't recognize. To take a permission back, connect the phone to a " +
                "computer with USB debugging on and run the command below with the app's package name and the " +
                "permission listed for it (for example android.permission.WRITE_SECURE_SETTINGS). Turn USB " +
                "debugging off again afterwards.",
            command = "adb shell pm revoke <package> <permission>",
        ),
        timeout = 15.seconds,
        failsWhen = "an app you installed holds WRITE_SECURE_SETTINGS, READ_LOGS, DUMP or INTERACT_ACROSS_USERS, " +
            "which only adb, Shizuku or root can grant",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val wanted = Power.entries.associateBy { it.permission }
        val granted = permissions.holders(wanted.keys)
        if (granted !is Reading.Value) {
            return Outcome.unknown("Could not read which apps hold system permissions", listOf(granted.toEvidence("Permissions")))
        }
        // Without the app list, apps that came with the phone (which hold these by privilege) can't be
        // told apart and would all count: Unknown, never a FAIL full of system apps.
        val apps = packages.installedApps()
        val inventory = (apps as? Reading.Value)?.value?.associateBy { it.packageName }
            ?: return Outcome.unknown(
                "Could not tell which apps holding system permissions came with the phone",
                listOf(apps.toEvidence("Installed apps")),
            )
        val held: Map<String, List<Power>> = granted.value
            .mapValues { (_, perms) -> perms.mapNotNull { wanted[it] }.sorted() }
            .filterValues { it.isNotEmpty() }
        // Apps that came with the phone hold these by privilege, which is how Android is built.
        val (preinstalled, installed) = held.keys.partition { originOf(it, inventory) == AppOrigin.PREINSTALLED }
        val exempt = installed.filter { it in NOT_COUNTED }
        val all = (installed - exempt.toSet())
            .map { Holder(AppRef(it, packages.label(it)), originOf(it, inventory)) }
            .sortedBy { it.app.label.lowercase() }
        val (trusted, counted) = context.splitTrusted(all) { it.app.packageName }

        val evidence = buildList {
            all.forEach { holder ->
                val powers = held.getValue(holder.app.packageName)
                add(
                    Evidence(
                        "Granted over adb",
                        "${holder.app.label} (${holder.app.packageName})",
                        granted.source,
                        note = withTrustNote(
                            powers.joinToString { "${it.shortName}: ${it.does}" } + "; " + holder.origin.note,
                            trusted = holder in trusted,
                        ),
                        packageName = holder.app.packageName,
                        trust = trustOf(counted = true, trusted = holder in trusted),
                    ),
                )
            }
            exempt.forEach { pkg ->
                add(
                    Evidence(
                        "Granted over adb",
                        "${packages.label(pkg)} ($pkg)",
                        granted.source,
                        note = held.getValue(pkg).joinToString { it.shortName } + "; " + NOT_COUNTED.getValue(pkg) + "; not counted",
                        packageName = pkg,
                        trust = Trust.NOT_COUNTED,
                    ),
                )
            }
            if (all.isEmpty() && exempt.isEmpty()) add(Evidence("Granted over adb", "none", granted.source))
            if (preinstalled.isNotEmpty()) {
                add(Evidence("Apps that came with the phone and hold them", preinstalled.size.toString(), granted.source))
            }
            // Droynis is left out of the holders; the ADB tier is the user granting it DUMP on purpose.
            if (Grant.DUMP in context.capabilities.grants) {
                add(Evidence("Granted over adb", "Droynis", OWN_GRANTS, note = "DUMP, for the ADB tier; this app; not counted"))
            }
        }
        if (counted.isEmpty() && trusted.isNotEmpty()) {
            return Outcome.pass(
                onlyTrusted("hold system permissions granted over adb", trusted.labels(), others = "apps that came with the phone"),
                evidence,
            )
        }
        if (counted.isEmpty()) {
            val summary = if (exempt.isEmpty()) {
                "No app you installed holds a system permission granted over adb"
            } else {
                "No counted apps hold these permissions. Listed separately: ${exempt.map(packages::label).joinNames()}"
            }
            return Outcome.pass(summary, evidence)
        }
        val verb = if (counted.size == 1) "holds" else "hold"
        return Outcome.fail(
            "${count(counted.size, "app")} $verb system permissions granted over adb: ${counted.labels().joinNames()}",
            evidence,
        )
    }

    private companion object {
        val OWN_GRANTS = Source("Droynis' own permissions", Grant.DUMP)

        /** Apps whose power these permissions don't add to, with why. */
        val NOT_COUNTED = mapOf(ShizukuAppsCheck.MANAGER to "Shizuku itself, which has adb's rights anyway (APPS-4016)")
    }
}
