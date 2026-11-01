package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate

/**
 * The package verifier that Play Protect (or an OEM equivalent) uses to scan an app before it is
 * installed. The setting is a global 0/1 switch; a check passes only on a "1" it actually read, so
 * an unset or unreadable value stays Unknown, never a pass.
 */
class PlayProtectCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "APPS-4015",
        category = Category.APPS,
        title = "App scanning (Play Protect)",
        severity = Severity.WARNING,
        explanation = "Before an app is installed, Android asks the package verifier (Play Protect on phones " +
            "with Google services, an OEM scanner on others) to check it against known malware. With the " +
            "verifier off, apps from any source install unchecked, so a sideloaded or repackaged app carrying " +
            "malware is not flagged.",
        remediation = Remediation(
            text = "Turn scanning back on in Play Protect (Play Store › your profile › Play Protect › Settings › " +
                "Scan apps with Play Protect), or under Settings › Security. The verifier only scans; it still " +
                "lets you install an app it warns about.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        failsWhen = "the install-time app verifier (Play Protect) is turned off",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val reading = settings.global(PACKAGE_VERIFIER_ENABLE)
        val evidence = listOf(reading.settingEvidence(PACKAGE_VERIFIER_ENABLE))
        return reading.evaluate("The app verifier setting", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.pass("App scanning is on", evidence)
                SwitchState.OFF -> Outcome.fail("App scanning is off: apps install without a malware check", evidence)
                // Unset or an unexpected value proves nothing; Android's default is "on", but we don't assume it.
                else -> Outcome.unknown("Could not tell whether app scanning is on", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Global.PACKAGE_VERIFIER_ENABLE`: the master switch for the install-time verifier. */
        const val PACKAGE_VERIFIER_ENABLE = "package_verifier_enable"
    }
}
