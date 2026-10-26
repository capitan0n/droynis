package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * User apps on Android's power allowlist: exempt from Doze and App Standby, so they may run in the
 * background at any time. `PowerManager.isIgnoringBatteryOptimizations` answers for any package
 * Droynis can see, with no permission. Apps that came with the phone are on the vendor's own
 * allowlist and are not asked about.
 */
class BatteryOptimizationCheck(
    private val battery: BatteryProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4013",
        category = Category.APPS,
        title = "Apps that skip battery optimization",
        severity = Severity.INFO,
        explanation = "An app set to \"Unrestricted\" battery use (\"Not optimized\" on older Android) is exempt " +
            "from Doze and App Standby, so it can wake the phone and keep running in the background at any " +
            "time. Messengers, sync and automation apps use this to work on time; stalkerware and " +
            "remote-access tools ask for it to keep running unnoticed. Apps that came with the phone aren't " +
            "listed. This check is for your information and doesn't count in the score.",
        remediation = Remediation(
            text = "Open Settings › Apps › the app › App battery usage (Battery on some phones) and choose " +
                "\"Optimized\" for apps that don't need to run in the background. Uninstall apps you don't recognize.",
            settingsActions = listOf(SettingsActions.BATTERY_OPTIMIZATION, SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an app you installed may skip battery optimization (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        if (apps !is Reading.Value) {
            return Outcome.unknown("Could not read the installed apps", listOf(apps.toEvidence("Installed apps")))
        }
        val user = apps.value.filter { !it.isSystem }
        val inspected = Evidence("User apps inspected", user.size.toString(), apps.source)
        if (user.isEmpty()) return Outcome.pass(NONE, listOf(inspected))

        val exempt = battery.unrestricted(user.map { it.packageName })
        if (exempt !is Reading.Value) {
            return Outcome.unknown(
                "Could not read which apps skip battery optimization",
                listOf(inspected, exempt.toEvidence("Battery optimization")),
            )
        }
        val inventory = apps.value.associateBy { it.packageName }
        val holders = user.filter { it.packageName in exempt.value }
            .map { Holder(AppRef(it.packageName, packages.label(it.packageName)), originOf(it.packageName, inventory)) }
            .sortedBy { it.app.label.lowercase() }
        val evidence = listOf(inspected) + holders.map { it.evidence("Unrestricted battery use", exempt.source) }
        if (holders.isEmpty()) return Outcome.pass(NONE, evidence)

        // Information only: a sideloaded app is named, but never raises the severity.
        return Outcome.fail(
            "${count(holders.size, "app")} may run in the background without limits: " +
                holders.map { it.app.label }.joinNames() + sideloadedSuffix(holders),
            evidence,
        )
    }

    private companion object {
        const val NONE = "No app you installed skips battery optimization"
    }
}
