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
import io.github.capitan0n.droynis.core.evaluate

/**
 * The package verifier that Play Protect (or an OEM equivalent) uses to scan an app before it is
 * installed. Two global settings describe general scanning: Android's master switch, which most phones leave unset,
 * and the answer Play Protect stores when its "Scan apps" switch is turned on or off. The check
 * passes only on an "on" it actually read from one of them, so unset or unreadable values stay
 * Unknown, never a pass. Android hides the second from apps since Android 12; the settings probe
 * reads it through Shizuku or root where one is connected. The separate ADB switch is also shown.
 */
class PlayProtectCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "APPS-4015",
        category = Category.APPS,
        title = "App scanning (Play Protect)",
        severity = Severity.WARNING,
        explanation = "Before an app is installed, Android asks the package verifier (Play Protect on phones " +
            "with Google services, an OEM scanner on others) to check it against known malware. With the " +
            "verifier off, apps from any source install unchecked, so a sideloaded or repackaged app carrying " +
            "malware is not flagged. Android also has a separate switch for verifying apps installed through ADB. " +
            "Device policy can require ADB verification even when that switch is off.",
        remediation = Remediation(
            text = "Turn scanning back on in Play Protect (Play Store › your profile › Play Protect › Settings › " +
                "Scan apps with Play Protect), or under Settings › Security. The verifier only scans; it still " +
                "lets you install an app it warns about. For ADB installs, turn on Verify apps over USB in Developer options.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        failsWhen = "the install-time app verifier, Play Protect scanning, or the separate ADB verification switch is off",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val verifier = settings.global(PACKAGE_VERIFIER_ENABLE)
        val consent = settings.global(PACKAGE_VERIFIER_USER_CONSENT)
        val adb = settings.global(PACKAGE_VERIFIER_INCLUDE_ADB)
        val evidence = listOf(
            verifier.settingEvidence(PACKAGE_VERIFIER_ENABLE),
            consent.settingEvidence(PACKAGE_VERIFIER_USER_CONSENT),
            adb.settingEvidence("Verify apps installed through ADB"),
        )
        val master = (verifier as? Reading.Value)?.let { switchState(it.value) }
        val playProtect = (consent as? Reading.Value)?.let { switchState(it.value, on = CONSENT_GIVEN, off = CONSENT_DECLINED) }
        return when {
            master == SwitchState.OFF -> Outcome.fail("App scanning is off: apps install without a malware check", evidence)
            playProtect == SwitchState.OFF ->
                Outcome.fail("Play Protect's app scanning is turned off: apps install without a malware check", evidence)
            (adb as? Reading.Value)?.let { switchState(it.value) } == SwitchState.OFF ->
                Outcome.fail("The switch to verify apps installed through ADB is off", evidence)
            master == SwitchState.ON || playProtect == SwitchState.ON -> Outcome.pass("App scanning is on", evidence)
            // Unset or an unexpected value proves nothing; Android's default is "on", but we don't assume it.
            else -> verifier.evaluate("The app verifier setting", evidence) {
                Outcome.unknown("Could not tell whether app scanning is on", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Global.PACKAGE_VERIFIER_ENABLE`: the master switch for the install-time verifier. */
        const val PACKAGE_VERIFIER_ENABLE = "package_verifier_enable"

        /**
         * `Settings.Global.PACKAGE_VERIFIER_USER_CONSENT`: what the user answered Play Protect, which
         * its "Scan apps with Play Protect" switch writes. 1 is on, -1 is off, 0 or unset is not asked yet.
         */
        const val PACKAGE_VERIFIER_USER_CONSENT = "package_verifier_user_consent"

        const val PACKAGE_VERIFIER_INCLUDE_ADB = "verifier_verify_adb_installs"

        private val CONSENT_GIVEN = setOf("1")
        private val CONSENT_DECLINED = setOf("-1")
    }
}
