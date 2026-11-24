package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.PermissionProbe
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
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

class FullScreenAlertsCheck(
    private val dumpsys: Dumpsys,
    private val packages: PackageInventory,
    private val permissions: PermissionProbe,
) : Check {
    override val spec = CheckSpec(
        id = "APPS-4112",
        category = Category.APPS,
        title = "Apps allowed to show full-screen alerts",
        severity = Severity.INFO,
        minSdk = 34,
        requires = setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS),
        timeout = 15.seconds,
        explanation = "Full-screen alerts can open over the lock screen for urgent events such as calls and alarms. " +
            "This lists the apps Android allows to request them. Notification settings and the state of the phone " +
            "still determine how an alert appears.",
        remediation = Remediation(
            text = "Review full-screen alerts under Settings › Apps › Special app access.",
            settingsActions = listOf(SettingsActions.APPS),
            appSettingsActions = listOf(SettingsActions.FULL_SCREEN_ALERTS),
        ),
        failsWhen = "never (reports apps with full-screen alert access)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = dumpsys.dump(BackgroundSensorUseCheck.SERVICE)
        if (dump !is Reading.Value) {
            return Outcome.unknown("Could not read full-screen alert access", listOf(dump.toEvidence("App-op modes")))
        }
        val modes = AppOpModes.allModes(dump.value, OP)
        if (modes !is AppOpModes.Result.Parsed) {
            return Outcome.unknown("Could not verify full-screen alert access",
                listOf(Evidence("App-op modes", null, dump.source, note = "unrecognized per-app data")))
        }
        val apps = packages.installedApps()
        val permission = permissions.holders(setOf(PERMISSION))
        val inventory = listOf(
            apps.toEvidence("Installed apps") { it.size.toString() },
            permission.toEvidence("Apps granted the underlying full-screen permission") { it.size.toString() },
        )
        if (apps !is Reading.Value || permission !is Reading.Value) {
            return Outcome.unknown("Could not verify the app and permission inventory", inventory)
        }

        // A UID override also applies to packages the app-ops dump did not list under that UID.
        val uidModes = modes.grants.filter { it.uidWide }
        val byUid = uidModes.associateBy { AppOpModes.uidOf(it.uid) ?: it.uid.toIntOrNull() }
        val byPackage = modes.grants.filterNot { it.uidWide }.associateBy { it.packageName }
        if (null in byUid || modes.grants.any { it.mode !in KNOWN_MODES }) {
            return Outcome.unknown("Could not verify all full-screen alert modes", inventory)
        }
        val allowed = apps.value.filter { it.isEnabled }.mapNotNull { app ->
            val mode = (byUid[app.uid] ?: byPackage[app.packageName])?.mode ?: "default"
            val access = when {
                app.targetSdk < 29 -> "Android compatibility for older apps"
                mode == "allow" -> "allowed"
                mode == "foreground" -> "allowed in the foreground"
                mode == "default" && app.packageName in permission.value -> "allowed by the app's permission"
                else -> return@mapNotNull null
            }
            val label = packages.label(app.packageName)
            val source = if (mode == "default" && app.targetSdk >= 29) permission.source else dump.source
            Evidence("Full-screen alerts", "$label (${app.packageName})", source,
                note = if (app.isSystem) "$access, built-in" else access, packageName = app.packageName)
        }
        val summary = if (allowed.isEmpty()) "No app has full-screen alert access"
            else "Full-screen alert access: ${allowed.mapNotNull { it.packageName }.map(packages::label).distinct().joinNames()}"
        return Outcome.pass(summary, inventory + allowed)
    }

    private companion object {
        const val OP = "USE_FULL_SCREEN_INTENT"
        const val PERMISSION = "android.permission.USE_FULL_SCREEN_INTENT"
        val KNOWN_MODES = setOf("allow", "foreground", "ignore", "deny", "default")
    }
}
