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

class UsbDebuggingCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2011",
        category = Category.ACCESS_CONTROL,
        title = "USB debugging",
        severity = Severity.WARNING,
        explanation = "With USB debugging on, any computer you have authorized can install apps, grant " +
            "them permissions, read shared storage and capture the screen through adb. It widens what " +
            "someone with physical access, or with control of a computer you once trusted, can do.",
        remediation = Remediation(
            text = "Turn off USB debugging in Developer options and tap \"Revoke USB debugging " +
                "authorizations\". Permissions granted to Droynis with adb stay granted afterwards.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val adb = settings.global(ADB_ENABLED)
        val evidence = listOf(adb.settingEvidence(ADB_ENABLED))
        return adb.evaluate("USB debugging state", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.fail("USB debugging is enabled", evidence)
                SwitchState.OFF ->
                    if (mayBeRedacted(context, raw)) {
                        Outcome.unknown(REDACTED_SUMMARY, evidence.map { it.redacted() })
                    } else {
                        Outcome.pass("USB debugging is disabled", evidence)
                    }
                // The system writes this key at boot, so its absence is itself suspicious.
                SwitchState.UNSET -> Outcome.unknown("$ADB_ENABLED is not set", evidence)
                SwitchState.UNEXPECTED -> Outcome.unknown("Unexpected value \"$raw\" for $ADB_ENABLED", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Global.ADB_ENABLED` */
        const val ADB_ENABLED = "adb_enabled"
    }
}
