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
 * Apps you installed that hold selected system permissions. Package Manager reports current grants.
 * Android can grant these permissions through app signing, system privileges or a development grant.
 * Shizuku's own permission is listed separately because APPS-4016 already covers its shell access.
 * APPS-4105 covers usage access through its app-op.
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
        title = "Apps with system permissions",
        severity = Severity.WARNING,
        explanation = "These permissions can let an app change secure settings, read system logs or service " +
            "diagnostics, or reach other users of the phone. Android can grant them based on app signing, " +
            "system privileges or a development grant through adb, Shizuku or root. This check reads which " +
            "permissions each app holds. The package manager does not identify how it received them.",
        remediation = Remediation(
            text = "Review the apps and permissions listed below. If you granted a permission with adb, " +
                "you can revoke that grant using the app's package name and the permission in the command below. " +
                "Permissions tied to app signing or system privileges may not be revocable this way.",
            command = "adb shell pm revoke <package> <permission>",
        ),
        timeout = 15.seconds,
        failsWhen = "an app you installed holds WRITE_SECURE_SETTINGS, READ_LOGS, DUMP or INTERACT_ACROSS_USERS",
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
        // List the preinstalled permission holders separately.
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
                        PERMISSIONS_HELD,
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
                        PERMISSIONS_HELD,
                        "${packages.label(pkg)} ($pkg)",
                        granted.source,
                        note = held.getValue(pkg).joinToString { it.shortName } + "; " + NOT_COUNTED.getValue(pkg) + "; not counted",
                        packageName = pkg,
                        trust = Trust.NOT_COUNTED,
                    ),
                )
            }
            if (all.isEmpty() && exempt.isEmpty()) add(Evidence(PERMISSIONS_HELD, "none", granted.source))
            if (preinstalled.isNotEmpty()) {
                add(Evidence("Apps that came with the phone and hold them", preinstalled.size.toString(), granted.source))
            }
            // Droynis is left out of the holders; the ADB tier is the user granting it DUMP on purpose.
            if (Grant.DUMP in context.capabilities.grants) {
                add(Evidence(PERMISSIONS_HELD, "Droynis", OWN_GRANTS, note = "DUMP, for the ADB tier; this app; not counted"))
            }
        }
        if (counted.isEmpty() && trusted.isNotEmpty()) {
            return Outcome.pass(
                onlyTrusted("hold these system permissions", trusted.labels(), others = "apps that came with the phone"),
                evidence,
            )
        }
        if (counted.isEmpty()) {
            val summary = if (exempt.isEmpty()) {
                "No app you installed holds any of these system permissions"
            } else {
                "No counted apps hold these permissions. Listed separately: ${exempt.map(packages::label).joinNames()}"
            }
            return Outcome.pass(summary, evidence)
        }
        val verb = if (counted.size == 1) "holds" else "hold"
        return Outcome.fail(
            "${count(counted.size, "app")} $verb system permissions: ${counted.labels().joinNames()}",
            evidence,
        )
    }

    private companion object {
        const val PERMISSIONS_HELD = "System permissions held"
        val OWN_GRANTS = Source("Droynis' own permissions", Grant.DUMP)

        /** Apps whose power these permissions don't add to, with why. */
        val NOT_COUNTED = mapOf(ShizukuAppsCheck.MANAGER to "Shizuku itself, which has adb's rights anyway (APPS-4016)")
    }
}
