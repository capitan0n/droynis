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

class StayAwakeCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2005",
        category = Category.ACCESS_CONTROL,
        title = "Stay awake while charging",
        severity = Severity.NOTICE,
        explanation = "With \"Stay awake\" on, the screen never turns off while the phone charges, so it " +
            "never locks either. Anyone who picks up a charging phone that was left unlocked gets in " +
            "without the PIN.",
        remediation = Remediation(
            text = "Turn off \"Stay awake\" in Developer options.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val stayOn = settings.global(STAY_ON_WHILE_PLUGGED_IN)
        val evidence = listOf(stayOn.settingEvidence(STAY_ON_WHILE_PLUGGED_IN))
        return stayOn.evaluate("Stay awake setting", evidence) { raw ->
            // A bit mask of charger types (AC, USB, wireless, dock); 0 means off.
            val mask = raw?.trim()?.toIntOrNull()
            when {
                raw == null -> Outcome.unknown("$STAY_ON_WHILE_PLUGGED_IN is not set", evidence)
                mask == null -> Outcome.unknown("Unexpected value \"$raw\" for $STAY_ON_WHILE_PLUGGED_IN", evidence)
                mask == 0 -> Outcome.pass("The screen turns off and locks while charging", evidence)
                else -> Outcome.fail("The screen stays on, unlocked, while charging", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Global.STAY_ON_WHILE_PLUGGED_IN` */
        const val STAY_ON_WHILE_PLUGGED_IN = "stay_on_while_plugged_in"
    }
}
