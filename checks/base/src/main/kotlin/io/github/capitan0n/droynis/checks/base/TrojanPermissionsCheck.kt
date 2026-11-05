package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.READ_SMS
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.RECEIVE_SMS
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.SYSTEM_ALERT_WINDOW
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps that ask for the three things a banking trojan needs together: an accessibility service to
 * read the screen and tap, SMS to catch login codes, and drawing over other apps for fake login
 * screens. Each is common alone; together they are rare outside automation apps.
 */
class TrojanPermissionsCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
    private val accessibility: AccessibilityProbe,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5005",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps with banking-trojan permissions",
        severity = Severity.WARNING,
        explanation = "Banking trojans need three things together: an accessibility service to read the screen and " +
            "tap for you, SMS access to catch login codes, and drawing over other apps to show fake login " +
            "screens. Droynis lists installed apps that ask for all three. Automation apps such as Tasker and " +
            "MacroDroid ask for them too; trust them if you use them.",
        remediation = Remediation(
            text = "Uninstall apps listed here that you don't recognize. For one you keep, turn its accessibility " +
                "service off while you don't need it (Settings › Accessibility) and remove its SMS permission.",
            settingsActions = listOf(SettingsActions.ACCESSIBILITY, SettingsActions.APPS),
        ),
        timeout = 30.seconds,
        failsWhen = "an installed app declares an accessibility service and asks for SMS and to draw over other apps " +
            "(critical when it came from outside an app store or its accessibility service is on)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = readSightings(footprints, packages) { return it }
        val evidence = mutableListOf(apps.inspected())
        val found = apps.all.filter { matches(it.footprint) }
        if (found.isEmpty()) return Outcome.pass(NONE, evidence)

        val enabled = accessibility.enabledServices()
        if (enabled !is Reading.Value) evidence += enabled.toEvidence("Accessibility services")
        val on = (enabled as? Reading.Value)?.value.orEmpty().mapTo(HashSet()) { it.packageName }

        val (trusted, counted) = context.splitTrusted(found) { it.packageName }
        evidence += found.map { app ->
            val details = if (app.packageName in on) "accessibility service on" else "accessibility service off"
            app.evidence("Banking-trojan permissions", apps.source, details, app in trusted, counted = true, showVisibility = false)
        }
        if (counted.isEmpty()) {
            return Outcome.pass(onlyTrusted("ask for all three", trusted.map { it.name }), evidence)
        }
        val critical = counted.any { it.origin == AppOrigin.SIDELOADED || it.packageName in on }
        return Outcome.fail(
            "${count(counted.size, "app")} with accessibility, SMS and overlay permissions: ${counted.names()}",
            evidence,
            escalation = Severity.CRITICAL.takeIf { critical },
        )
    }

    internal companion object {
        const val NONE = "No installed app asks for accessibility, SMS and drawing over other apps together"

        fun matches(footprint: AppFootprint): Boolean =
            footprint.accessibilityService &&
                (READ_SMS in footprint.requested || RECEIVE_SMS in footprint.requested) &&
                SYSTEM_ALERT_WINDOW in footprint.requested
    }
}
