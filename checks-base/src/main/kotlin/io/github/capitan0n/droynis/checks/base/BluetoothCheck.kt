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

class BluetoothCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "NETW-3004",
        category = Category.NETWORK,
        title = "Bluetooth",
        severity = Severity.NOTICE,
        explanation = "A radio that is on can be attacked: Bluetooth flaws such as BlueBorne and BLUFFS " +
            "let nearby attackers reach a phone without pairing. Leaving it on also makes the device " +
            "easier to notice and track nearby.",
        remediation = Remediation(
            text = "Turn Bluetooth off when you are not using headphones, a watch or a car.",
            settingsActions = listOf(SettingsActions.BLUETOOTH),
        ),
        failsWhen = "Bluetooth is on",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val state = settings.global(BLUETOOTH_ON)
        val evidence = listOf(state.settingEvidence(BLUETOOTH_ON))
        return state.evaluate("Bluetooth state", evidence) { raw ->
            // 1 = on, 2 = on while in airplane mode.
            when (switchState(raw, on = setOf("1", "2"))) {
                SwitchState.ON -> Outcome.fail("Bluetooth is on", evidence)
                SwitchState.OFF -> Outcome.pass("Bluetooth is off", evidence)
                SwitchState.UNSET -> Outcome.unknown("$BLUETOOTH_ON is not set", evidence)
                SwitchState.UNEXPECTED -> Outcome.unknown("Unexpected value \"$raw\" for $BLUETOOTH_ON", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Global.BLUETOOTH_ON` */
        const val BLUETOOTH_ON = "bluetooth_on"
    }
}
