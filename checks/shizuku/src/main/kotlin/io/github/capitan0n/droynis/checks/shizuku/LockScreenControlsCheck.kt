package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.NOT_SET
import io.github.capitan0n.droynis.checks.base.SwitchState
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.checks.base.settingEvidence
import io.github.capitan0n.droynis.checks.base.switchState
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate

/**
 * What the lock screen lets anyone do with device controls (Android 13+). SystemUI reads both
 * switches with a default of 0 (`ControlsSettingsRepositoryImpl`, Android 17). Without
 * [LOCKSCREEN_SHOW_CONTROLS] the controls, and the lock screen's Home shortcut, only open after
 * unlocking (`ControlsComponent.getVisibility`). With it, a control acts without the unlock when
 * [LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS] is on and its app doesn't mark it as needing authentication
 * (`ControlActionCoordinatorImpl.bouncerOrRun`). [LOCKSCREEN_SHOW_WALLET] only shows the cards:
 * whether one pays while locked is up to the wallet app and Secure NFC, so it is evidence only. All
 * three keys are hidden and not `@Readable` in Android 13 to 17.
 */
class LockScreenControlsCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2202",
        category = Category.ACCESS_CONTROL,
        title = "Device controls on the lock screen",
        severity = Severity.NOTICE,
        explanation = "Device controls switch smart home devices, such as lights, plugs, heating or a lock, " +
            "from the phone. With \"Show device controls\" and \"Use device controls\" (\"Control from locked " +
            "device\" on Android 13) both on, anyone holding your locked phone can use each control whose app " +
            "doesn't ask for the unlock; the app decides which ones do. Android hides these switches from apps; " +
            "the shell user Shizuku runs as can read them.",
        remediation = Remediation(
            text = "Open Settings › Display › Lock screen and turn off \"Use device controls\" (\"Control from " +
                "locked device\" on Android 13), or \"Show device controls\".",
            settingsActions = listOf(SettingsActions.LOCK_SCREEN, SettingsActions.DISPLAY, SettingsActions.SECURITY),
            highlightKey = "lockscreen_trivial_controls_switch",
        ),
        // "Control from locked device" arrived in Android 13.
        minSdk = 33,
        requires = setOf(Grant.SHIZUKU),
        failsWhen = "device controls can be used without unlocking the phone",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val show = settings.secure(LOCKSCREEN_SHOW_CONTROLS)
        val trivial = settings.secure(LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS)
        val wallet = settings.secure(LOCKSCREEN_SHOW_WALLET)
        val evidence = listOf(
            show.switchEvidence("Show device controls", LOCKSCREEN_SHOW_CONTROLS),
            trivial.switchEvidence("Use device controls", LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS),
            wallet.switchEvidence("Show wallet", LOCKSCREEN_SHOW_WALLET).let {
                if (it.value == null) it else it.copy(note = "only shows your cards; not counted")
            },
        )
        return show.evaluate("The \"Show device controls\" switch", evidence) { showRaw ->
            when (switchState(showRaw)) {
                SwitchState.OFF, SwitchState.UNSET -> Outcome.pass("Device controls open only after unlocking the phone", evidence)
                SwitchState.UNEXPECTED -> Outcome.unknown("Unexpected value \"$showRaw\" for $LOCKSCREEN_SHOW_CONTROLS", evidence)
                SwitchState.ON -> trivial.evaluate("The \"Use device controls\" switch", evidence) { raw ->
                    when (switchState(raw)) {
                        SwitchState.ON -> Outcome.fail("Device controls on the lock screen work without unlocking the phone", evidence)
                        SwitchState.OFF, SwitchState.UNSET ->
                            Outcome.pass("Device controls show on the lock screen, but each one asks for the unlock", evidence)
                        SwitchState.UNEXPECTED ->
                            Outcome.unknown("Unexpected value \"$raw\" for $LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS", evidence)
                    }
                }
            }
        }
    }

    /** "on", "off" or "(not set), off by default", under the name Settings shows and the key. */
    private fun Reading<String?>.switchEvidence(name: String, key: String): Evidence {
        val label = "$name ($key)"
        if (this !is Reading.Value) return settingEvidence(label)
        val shown = when (switchState(value)) {
            SwitchState.ON -> "on"
            SwitchState.OFF -> "off"
            SwitchState.UNSET -> "$NOT_SET, off by default"
            SwitchState.UNEXPECTED -> value.orEmpty()
        }
        return Evidence(label, shown, source)
    }

    companion object {
        /** `Settings.Secure.LOCKSCREEN_SHOW_CONTROLS`: "Show device controls". */
        const val LOCKSCREEN_SHOW_CONTROLS = "lockscreen_show_controls"

        /** `Settings.Secure.LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS`: "Use device controls" ("Control from locked device" in Android 13). */
        const val LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS = "lockscreen_allow_trivial_controls"

        /** `Settings.Secure.LOCKSCREEN_SHOW_WALLET`: "Show wallet". */
        const val LOCKSCREEN_SHOW_WALLET = "lockscreen_show_wallet"
    }
}
