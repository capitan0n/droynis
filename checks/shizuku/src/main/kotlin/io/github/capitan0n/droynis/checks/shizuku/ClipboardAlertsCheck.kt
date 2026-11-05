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
 * Android 12+ shows "<app> pasted from your clipboard" when an app reads what another app copied,
 * unless [CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS] is 0 (`ClipboardService.showAccessNotificationLocked`,
 * Android 17). The keyboard, the app the text came from and a few system services never trigger it.
 * When the key is unset, ClipboardService and Settings both fall back to the DeviceConfig flag
 * `clipboard/show_access_notifications`, true in AOSP (`ClipboardManager`), so unset is on. The key
 * is hidden and not `@Readable` in Android 12 to 17.
 */
class ClipboardAlertsCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "APPS-4202",
        category = Category.APPS,
        title = "Clipboard access alerts",
        severity = Severity.NOTICE,
        explanation = "What you copy often holds passwords, one-time codes, addresses or crypto wallet " +
            "addresses. Since Android 12 a short message tells you when an app reads it, so an app that " +
            "reads the clipboard without you pasting shows itself. Turning \"Show clipboard access\" off " +
            "hides that. Android hides this switch from apps; the shell user Shizuku runs as can read it.",
        remediation = Remediation(
            text = "Open Settings › Privacy (Settings › Security & privacy › Privacy controls on newer phones) " +
                "and turn on \"Show clipboard access\"; searching Settings for \"clipboard\" finds it too.",
            settingsActions = listOf(SettingsActions.PRIVACY_CONTROLS, SettingsActions.PRIVACY),
            highlightKey = "show_clip_access_notification",
        ),
        minSdk = 31,
        requires = setOf(Grant.SHIZUKU),
        failsWhen = "\"Show clipboard access\" is off, so apps read the clipboard silently",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val alerts = settings.secure(CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS)
        val evidence = listOf(
            if (alerts is Reading.Value && alerts.value == null) {
                Evidence(CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS, "$NOT_SET, on by default", alerts.source)
            } else {
                alerts.settingEvidence(CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS)
            },
        )
        return alerts.evaluate("The clipboard access setting", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.pass("Android tells you when an app reads the clipboard", evidence)
                SwitchState.UNSET -> Outcome.pass("Android tells you when an app reads the clipboard (its default)", evidence)
                SwitchState.OFF -> Outcome.fail("Android no longer tells you when an app reads the clipboard", evidence)
                SwitchState.UNEXPECTED ->
                    Outcome.unknown("Unexpected value \"$raw\" for $CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Secure.CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS`: "Show clipboard access". */
        const val CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS = "clipboard_show_access_notifications"
    }
}
