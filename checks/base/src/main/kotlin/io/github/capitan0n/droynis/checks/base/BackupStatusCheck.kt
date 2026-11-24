package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate

class BackupStatusCheck(private val settings: SystemSettings) : Check {
    override val spec = CheckSpec(
        id = "APPS-4022",
        category = Category.APPS,
        title = "Android backup status",
        severity = Severity.INFO,
        explanation = "This shows the Android backup switch for this profile. Backups made within individual " +
            "apps or through other services are outside this check.",
        remediation = Remediation("Search Settings for Backup to review what is included and when it last ran."),
        failsWhen = "never (reports the Android backup switch)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val backup = settings.secure("backup_enabled")
        val evidence = listOf(backup.settingEvidence("Android backup"))
        return backup.evaluate("The Android backup switch", evidence) { value ->
            when (switchState(value)) {
                SwitchState.ON -> Outcome.pass("Android backup is on", evidence)
                SwitchState.OFF -> Outcome.pass("Android backup is off", evidence)
                else -> Outcome.unknown("Could not verify the Android backup switch", evidence)
            }
        }
    }
}
