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
import io.github.capitan0n.droynis.core.toEvidence

class LockScreenUsersCheck(
    private val settings: SystemSettings,
    private val canAddUsers: () -> Reading<Boolean>,
) : Check {
    override val spec = CheckSpec(
        id = "ACCS-2015",
        category = Category.ACCESS_CONTROL,
        title = "Add users from the lock screen",
        severity = Severity.NOTICE,
        explanation = "Android can let someone start adding a user or guest from the lock screen. " +
            "A new user has separate apps and data, but can use the phone without opening your profile.",
        remediation = Remediation(
            text = "Open Settings › System › Multiple users and turn off Add users from lock screen.",
            settingsActions = listOf(SettingsActions.USER_SETTINGS),
        ),
        failsWhen = "the lock-screen switch for adding users is on and the profile can add users",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val allowed = canAddUsers()
        val support = listOf(allowed.toEvidence("Can add users in this profile"))
        return allowed.evaluate("Multiple-user support", support) {
            if (!it) return@evaluate Outcome.unsupported("This profile cannot add users", support)
            val switch = settings.global("add_users_when_locked")
            val evidence = support + switch.settingEvidence("Add users from lock screen")
            switch.evaluate("The lock-screen user setting", evidence) { value ->
                when (switchState(value)) {
                    SwitchState.ON -> {
                        val switcher = settings.global("user_switcher_enabled")
                        val details = evidence + switcher.settingEvidence("Multiple users switch")
                        if (switcher is Reading.Value && switchState(switcher.value) == SwitchState.OFF) {
                            Outcome.unsupported("The user switcher is off", details)
                        } else {
                            Outcome.fail("The lock-screen switch for adding users is on", details)
                        }
                    }
                    SwitchState.OFF -> Outcome.pass("Add users from the lock screen is off", evidence)
                    else -> Outcome.unknown("Could not verify the lock-screen user setting", evidence)
                }
            }
        }
    }
}
