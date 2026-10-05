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
import io.github.capitan0n.droynis.core.evaluate

class OemUnlockingCheck(private val properties: SystemProperties) : Check {

    override val spec = CheckSpec(
        id = "INTG-1041",
        category = Category.DEVICE_INTEGRITY,
        title = "OEM unlocking",
        severity = Severity.NOTICE,
        explanation = "While OEM unlocking is allowed, the bootloader can be unlocked from a computer in " +
            "minutes. Unlocking wipes your data, but it also defeats Factory Reset Protection, so a stolen " +
            "phone can be reset and resold, and it is the first step to installing a modified system.",
        remediation = Remediation(
            text = "Turn off OEM unlocking in Developer options. The switch is greyed out while the bootloader " +
                "is unlocked or when the carrier does not allow unlocking.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
        failsWhen = "the OEM unlocking switch is on",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val props = properties.all()
        val values = (props as? Reading.Value)?.value.orEmpty()
        val evidence = if (props is Reading.Value) {
            listOf(OEM_UNLOCK_ALLOWED, OEM_UNLOCK_SUPPORTED).map { Evidence(it, values[it] ?: "(not readable)", props.source) }
        } else {
            emptyList()
        }
        return props.evaluate("System properties", evidence) {
            when {
                values[OEM_UNLOCK_ALLOWED] == "1" -> Outcome.fail("OEM unlocking is allowed", evidence)
                values[OEM_UNLOCK_ALLOWED] == "0" -> Outcome.pass("OEM unlocking is off", evidence)
                values[OEM_UNLOCK_SUPPORTED] == "0" -> Outcome.pass("This phone does not allow bootloader unlocking", evidence)
                else -> Outcome.unknown("This phone does not let apps read the OEM unlocking switch", evidence)
            }
        }
    }

    companion object {
        /** Mirrors the OEM unlocking switch; set by the system from the persistent data block. */
        const val OEM_UNLOCK_ALLOWED = "sys.oem_unlock_allowed"
        const val OEM_UNLOCK_SUPPORTED = "ro.oem_unlock_supported"
    }
}
