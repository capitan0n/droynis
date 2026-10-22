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

/**
 * Android 11+ notification history. While it is on, system_server saves each notification's app,
 * title, text and icon to /data/system_ce/<user>/notification_history and keeps 24 hours of it.
 * That copy outlives the notification and the app's own copy of the message, like the iOS
 * notification store the FBI read deleted Signal messages from.
 */
class NotificationHistoryCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2008",
        category = Category.ACCESS_CONTROL,
        title = "Notification history",
        severity = Severity.NOTICE,
        explanation = "With notification history on, Android saves the text of every notification from the " +
            "last 24 hours, message previews and one-time login codes included. The copy stays after you " +
            "dismiss the notification and after the app deletes the message or makes it disappear. Anyone " +
            "who gets into the unlocked phone can scroll through it, and forensic tools can extract it.",
        remediation = Remediation(
            text = "Turn off notification history (Settings › Notifications › Notification history); Android " +
                "then deletes what it saved. In messaging apps, also hide message content in notifications, " +
                "for example in Signal under Settings › Notifications › Show.",
            settingsActions = listOf(
                SettingsActions.NOTIFICATION_HISTORY,
                SettingsActions.NOTIFICATIONS,
            ),
        ),
        minSdk = 30,
        failsWhen = "notification history is on, keeping 24 hours of notification text",
    )

    override suspend fun run(context: ScanContext): Outcome {
        // Hidden but marked @Readable, so apps targeting API 31+ may read it. When it is denied
        // anyway, the platform retries through Shizuku or root, else this check is UNKNOWN.
        val history = settings.secure(NOTIFICATION_HISTORY_ENABLED)
        val evidence = listOf(history.settingEvidence(NOTIFICATION_HISTORY_ENABLED))
        return history.evaluate("Notification history setting", evidence) { raw ->
            when (switchState(raw)) {
                SwitchState.ON -> Outcome.fail("Notification history is on", evidence)
                // NotificationHistoryManager reads the key with a default of 0, so unset means off.
                SwitchState.OFF, SwitchState.UNSET -> Outcome.pass("Notification history is off", evidence)
                SwitchState.UNEXPECTED ->
                    Outcome.unknown("Unexpected value \"$raw\" for $NOTIFICATION_HISTORY_ENABLED", evidence)
            }
        }
    }

    companion object {
        /** `Settings.Secure.NOTIFICATION_HISTORY_ENABLED` (hidden, readable) */
        const val NOTIFICATION_HISTORY_ENABLED = "notification_history_enabled"
    }
}
