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

class PasswordVisibilityCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2003",
        category = Category.ACCESS_CONTROL,
        title = "Password visibility",
        severity = Severity.NOTICE,
        explanation = "With \"Show passwords\" on, each character you type into a password field stays " +
            "visible for a moment. Someone looking over your shoulder, a screen recording or a malicious " +
            "accessibility service can pick it up.",
        remediation = Remediation(
            text = "Turn off \"Show passwords\" (Settings › Privacy on most phones, Settings › Security on " +
                "older ones).",
            settingsActions = listOf(SettingsActions.PRIVACY, SettingsActions.SECURITY),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val shown = settings.system(TEXT_SHOW_PASSWORD)
        val evidence = listOf(shown.settingEvidence(TEXT_SHOW_PASSWORD))
        return shown.evaluate("Password visibility", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.fail("Typed password characters are shown briefly", evidence)
                // Android reads this key with a default of 1 (TextKeyListener), so unset means shown.
                SwitchState.UNSET -> Outcome.fail("Typed password characters are shown briefly (Android default)", evidence)
                SwitchState.OFF -> Outcome.pass("Password characters stay hidden while you type", evidence)
                SwitchState.UNEXPECTED -> Outcome.unknown("Unexpected value \"$raw\" for $TEXT_SHOW_PASSWORD", evidence)
            }
        }
    }

    companion object {
        /** `Settings.System.TEXT_SHOW_PASSWORD` */
        const val TEXT_SHOW_PASSWORD = "show_password"
    }
}
