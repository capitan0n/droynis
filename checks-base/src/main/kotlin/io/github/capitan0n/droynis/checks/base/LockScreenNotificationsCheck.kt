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

class LockScreenNotificationsCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2004",
        category = Category.ACCESS_CONTROL,
        title = "Lock screen notifications",
        severity = Severity.NOTICE,
        explanation = "Notifications on the lock screen can be read without unlocking the phone. Message " +
            "previews and one-time login codes are then visible to anyone who picks it up.",
        remediation = Remediation(
            text = "In the notification settings, set notifications on the lock screen to hide sensitive " +
                "content, or not to show at all.",
            settingsActions = listOf(
                SettingsActions.LOCK_SCREEN_NOTIFICATIONS,
                SettingsActions.NOTIFICATIONS,
                SettingsActions.SECURITY,
            ),
        ),
        failsWhen = "notification content is visible while the phone is locked",
    )

    override suspend fun run(context: ScanContext): Outcome {
        // Both keys are hidden but marked @Readable, so apps targeting API 31+ may read them.
        val show = settings.secure(LOCK_SCREEN_SHOW_NOTIFICATIONS)
        val content = settings.secure(LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS)
        val evidence = listOf(
            show.settingEvidence(LOCK_SCREEN_SHOW_NOTIFICATIONS),
            content.settingEvidence(LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS),
        )
        return show.evaluate("Lock screen notification setting", evidence) { showRaw ->
            when (switchState(showRaw)) {
                SwitchState.OFF -> Outcome.pass("No notifications are shown on the lock screen", evidence)
                SwitchState.UNEXPECTED ->
                    Outcome.unknown("Unexpected value \"$showRaw\" for $LOCK_SCREEN_SHOW_NOTIFICATIONS", evidence)
                // SystemUI reads the key with a default of 1, so unset means shown.
                SwitchState.ON, SwitchState.UNSET -> content.evaluate("Lock screen notification content", evidence) {
                    when (switchState(it)) {
                        SwitchState.ON -> Outcome.fail("Notification content is visible on the lock screen", evidence)
                        SwitchState.OFF -> Outcome.pass("The lock screen hides sensitive notification content", evidence)
                        SwitchState.UNSET -> Outcome.unknown("$LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS is not set", evidence)
                        SwitchState.UNEXPECTED ->
                            Outcome.unknown("Unexpected value \"$it\" for $LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS", evidence)
                    }
                }
            }
        }
    }

    companion object {
        /** `Settings.Secure.LOCK_SCREEN_SHOW_NOTIFICATIONS` (hidden, readable) */
        const val LOCK_SCREEN_SHOW_NOTIFICATIONS = "lock_screen_show_notifications"

        /** `Settings.Secure.LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS` (hidden, readable) */
        const val LOCK_SCREEN_ALLOW_PRIVATE_NOTIFICATIONS = "lock_screen_allow_private_notifications"
    }
}
