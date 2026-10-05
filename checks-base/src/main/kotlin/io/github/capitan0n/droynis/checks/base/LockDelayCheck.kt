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

class LockDelayCheck(private val settings: SystemSettings, private val keyguard: Keyguard) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2006",
        category = Category.ACCESS_CONTROL,
        title = "Lock after screen timeout",
        severity = Severity.NOTICE,
        explanation = "When the screen turns off by itself, Android waits this long before it asks for " +
            "your PIN again. Anyone who picks the phone up in that window gets in without it, which is " +
            "how many phone thefts work. The power button can lock at once, but apps can't read that " +
            "setting.",
        remediation = Remediation(
            text = "Under Settings › Security › Screen lock (gear icon), set Lock after screen timeout to " +
                "30 seconds or less, and turn on \"Power button instantly locks\".",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        failsWhen = "the phone stays unlocked for more than 30 seconds after the screen turns off",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val secure = keyguard.isDeviceSecure()
        val delay = settings.secure(LOCK_AFTER_TIMEOUT)
        val evidence = listOf(secure.toEvidence("Device secure"), delay.settingEvidence("$LOCK_AFTER_TIMEOUT (ms)"))

        if (secure is Reading.Value && !secure.value) {
            return Outcome.unsupported("No screen lock is set, so there is nothing to lock", evidence)
        }
        if (secure !is Reading.Value) {
            return Outcome.unknown("Could not tell whether a screen lock is set", evidence)
        }
        return delay.evaluate("Lock delay", evidence) { raw ->
            // Unset means the phone's built-in default (5 seconds in AOSP), which apps can't confirm.
            if (raw == null) {
                return@evaluate Outcome.unknown(
                    "Not set, so the phone uses its built-in default (5 seconds on most phones). " +
                        "Pick a value in Settings to let Droynis read it",
                    evidence,
                )
            }
            val millis = raw.trim().toLongOrNull()?.takeIf { it >= 0 }
                ?: return@evaluate Outcome.unknown("Unrecognized lock delay \"$raw\"", evidence)
            if (millis <= MAX_MILLIS) {
                Outcome.pass("Locks ${describe(millis)} after the screen turns off", evidence)
            } else {
                Outcome.fail("Stays unlocked for ${describe(millis)} after the screen turns off", evidence)
            }
        }
    }

    private fun describe(millis: Long): String = when {
        millis == 0L -> "immediately"
        millis >= MINUTE && millis % MINUTE == 0L -> count((millis / MINUTE).toInt(), "minute")
        else -> count((millis / SECOND).toInt(), "second")
    }

    companion object {
        /** `Settings.Secure.LOCK_SCREEN_LOCK_AFTER_TIMEOUT`, hidden from the SDK but `@Readable` (Android 17). */
        const val LOCK_AFTER_TIMEOUT = "lock_screen_lock_after_timeout"

        /** Up to 30 seconds passes. */
        const val MAX_MILLIS = 30_000L

        private const val SECOND = 1_000L
        private const val MINUTE = 60_000L
    }
}
