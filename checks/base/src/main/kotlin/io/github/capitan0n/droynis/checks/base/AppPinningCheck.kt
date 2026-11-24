package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class AppPinningCheck(private val settings: SystemSettings, private val keyguard: Keyguard) : Check {
    override val spec = CheckSpec(
        id = "ACCS-2014",
        category = Category.ACCESS_CONTROL,
        title = "Unlock required after app pinning",
        severity = Severity.NOTICE,
        explanation = "App pinning keeps one app on screen when you hand your phone to someone. " +
            "Requiring your screen lock when they unpin keeps them from opening your other apps.",
        remediation = Remediation(
            text = "Search Settings for App pinning and turn on the option to require unlocking after unpinning.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        failsWhen = "app pinning is on and unpinning does not require unlocking",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val pinning = settings.system("lock_to_app_enabled")
        val pinningEvidence = pinning.settingEvidence("App pinning")
        return pinning.evaluate("App pinning", listOf(pinningEvidence)) { value ->
            when (switchState(value)) {
                SwitchState.OFF, SwitchState.UNSET -> Outcome.unsupported("App pinning is off", listOf(pinningEvidence))
                SwitchState.ON -> checkUnlock(pinningEvidence)
                else -> Outcome.unknown("Could not verify whether app pinning is on", listOf(pinningEvidence))
            }
        }
    }

    private fun checkUnlock(pinning: Evidence): Outcome {
        val exitLock = settings.secure("lock_to_app_exit_locked")
        val evidence = listOf(pinning, exitLock.settingEvidence("Require unlock after unpinning"))
        if (exitLock !is Reading.Value) return Outcome.unknown("Could not verify the unpinning setting", evidence)
        val state = switchState(exitLock.value)
        if (state == SwitchState.OFF) {
            return Outcome.fail("A pinned app can be unpinned without unlocking", evidence)
        }
        if (state == SwitchState.UNEXPECTED) {
            return Outcome.unknown("Could not verify the unpinning setting", evidence)
        }
        // With no explicit setting, Android falls back to whether the user has a screen lock.
        val secure = keyguard.isDeviceSecure()
        val withLock = evidence + secure.toEvidence("Secure screen lock")
        return secure.evaluate("The screen lock", withLock) {
            if (it) Outcome.pass("Unpinning an app requires unlocking", withLock)
            else Outcome.fail("App pinning is on without a secure screen lock", withLock)
        }
    }
}
