package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate

/**
 * Android 17 hides the switch from apps (it reads "0"), so there a "0" is UNKNOWN unless something
 * that lives in Developer options is seen on: USB or wireless debugging. Settings turns both off
 * with Developer options, so either one on shows Developer options are on.
 */
class DeveloperOptionsCheck(private val settings: SystemSettings, private val usb: UsbProbe) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2010",
        category = Category.ACCESS_CONTROL,
        title = "Developer options",
        severity = Severity.NOTICE,
        explanation = "Developer options unlock debugging features such as USB and wireless debugging, " +
            "mock locations and OEM unlocking. They are not meant for everyday use, and keeping them " +
            "hidden lowers the chance of a risky switch being left on.",
        remediation = Remediation(
            text = "Turn Developer options off with the switch at the top of the Developer options " +
                "screen. Permissions granted to Droynis with adb stay granted.",
            settingsActions = listOf(SettingsActions.DEVELOPER_OPTIONS),
        ),
        failsWhen = "developer options are on",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = settings.global(DEVELOPMENT_SETTINGS_ENABLED)
        val evidence = listOf(enabled.settingEvidence(DEVELOPMENT_SETTINGS_ENABLED))
        return enabled.evaluate("Developer options state", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.fail("Developer options are enabled", evidence)
                SwitchState.OFF ->
                    if (enabled.mayBeRedacted(context)) {
                        redacted(evidence, context)
                    } else {
                        Outcome.pass("Developer options are disabled", evidence)
                    }
                // Settings writes this key only when the user toggles it; unset means never enabled.
                // A redacting platform returns its placeholder instead, so unset is never redacted.
                SwitchState.UNSET -> Outcome.pass("Developer options have never been enabled", evidence)
                SwitchState.UNEXPECTED ->
                    Outcome.unknown("Unexpected value \"$raw\" for $DEVELOPMENT_SETTINGS_ENABLED", evidence)
            }
        }
    }

    private fun redacted(setting: List<Evidence>, context: ScanContext): Outcome {
        val usbDebugging = settings.global(UsbDebuggingCheck.ADB_ENABLED)
        val wirelessDebugging = settings.global(WirelessDebuggingCheck.ADB_WIFI_ENABLED)
        val usbState = usb.state()
        val adbSetting = usbDebugging.settingEvidence(UsbDebuggingCheck.ADB_ENABLED)
        val evidence = setting.map { it.redacted() } + listOf(
            if (usbDebugging.mayBeRedacted(context)) adbSetting.redacted() else adbSetting,
            wirelessDebugging.settingEvidence(WirelessDebuggingCheck.ADB_WIFI_ENABLED),
            usbState.usbEvidence(),
        )
        val proof = when {
            usbDebugging.isOn() -> "USB debugging is on"
            wirelessDebugging.isOn() -> "wireless debugging is on"
            usbState.provesAdbOn() -> "a connected computer is using adb"
            else -> return Outcome.unknown(REDACTED_SUMMARY, evidence)
        }
        return Outcome.fail("Developer options are on: $proof", evidence)
    }

    companion object {
        /** `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` */
        const val DEVELOPMENT_SETTINGS_ENABLED = "development_settings_enabled"
    }
}
