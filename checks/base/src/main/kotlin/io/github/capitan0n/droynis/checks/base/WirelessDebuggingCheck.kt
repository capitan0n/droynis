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

class WirelessDebuggingCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2012",
        category = Category.ACCESS_CONTROL,
        title = "Wireless debugging",
        severity = Severity.WARNING,
        explanation = "Wireless debugging exposes adb on the Wi-Fi network. Any computer you have paired " +
            "can then install apps and control the phone over the network, without a cable.",
        remediation = Remediation(
            text = "Turn off Wireless debugging in Developer options and remove paired devices you no " +
                "longer use. Android also turns it off when you leave the Wi-Fi network.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
        minSdk = 30,
        failsWhen = "adb over Wi-Fi is on",
    )

    override suspend fun run(context: ScanContext): Outcome {
        // Not a public constant; apps targeting API 31+ can read it only while the platform marks it
        // readable, otherwise the probe reports access denied and this check is UNKNOWN.
        val wifiAdb = settings.global(ADB_WIFI_ENABLED)
        val evidence = listOf(wifiAdb.settingEvidence(ADB_WIFI_ENABLED))
        return wifiAdb.evaluate("Wireless debugging state", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.fail("Wireless debugging is on", evidence)
                SwitchState.OFF -> Outcome.pass("Wireless debugging is off", evidence)
                SwitchState.UNSET -> Outcome.unknown("$ADB_WIFI_ENABLED is not set", evidence)
                SwitchState.UNEXPECTED -> Outcome.unknown("Unexpected value \"$raw\" for $ADB_WIFI_ENABLED", evidence)
            }
        }
    }

    companion object {
        const val ADB_WIFI_ENABLED = "adb_wifi_enabled"
    }
}
