package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity

class ScanningCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "NETW-3009",
        category = Category.NETWORK,
        title = "Wi-Fi and Bluetooth scanning",
        severity = Severity.NOTICE,
        explanation = "With these on, the phone keeps scanning for Wi-Fi networks and Bluetooth devices " +
            "even when you turn Wi-Fi and Bluetooth off, to help locate you. The radios stay active, " +
            "so turning them off doesn't close their attack surface or stop location from working.",
        remediation = Remediation(
            text = "Turn off Wi-Fi scanning and Bluetooth scanning under Settings › Location › Location " +
                "services (on older Android: Location › Scanning).",
            settingsActions = listOf(SettingsActions.LOCATION),
        ),
        failsWhen = "Wi-Fi or Bluetooth scanning is on",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val switches = listOf(
            "Wi-Fi scanning" to settings.global(WIFI_SCAN_ALWAYS_AVAILABLE),
            "Bluetooth scanning" to settings.global(BLE_SCAN_ALWAYS_AVAILABLE),
        )
        val evidence = listOf(
            switches[0].second.settingEvidence(WIFI_SCAN_ALWAYS_AVAILABLE),
            switches[1].second.settingEvidence(BLE_SCAN_ALWAYS_AVAILABLE),
        )
        val states = switches.map { (name, reading) -> name to (reading as? Reading.Value)?.let { switchState(it.value) } }

        val on = states.filter { it.second == SwitchState.ON }.map { it.first }
        if (on.isNotEmpty()) {
            return Outcome.fail("${on.joinToString(" and ")} ${if (on.size == 1) "is" else "are"} on", evidence)
        }
        if (states.all { it.second == SwitchState.OFF }) {
            return Outcome.pass("Wi-Fi and Bluetooth scanning are off", evidence)
        }
        val unclear = states.filter { it.second != SwitchState.OFF }.map { it.first }
        return Outcome.unknown("Could not tell whether ${unclear.joinToString(" or ")} is on", evidence)
    }

    companion object {
        /** `Settings.Global.WIFI_SCAN_ALWAYS_AVAILABLE`, hidden from the SDK but `@Readable` (Android 17). */
        const val WIFI_SCAN_ALWAYS_AVAILABLE = "wifi_scan_always_enabled"

        /** `Settings.Global.BLE_SCAN_ALWAYS_AVAILABLE`, a system API but `@Readable` (Android 17). */
        const val BLE_SCAN_ALWAYS_AVAILABLE = "ble_scan_always_enabled"
    }
}
