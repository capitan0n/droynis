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

class ScreenTimeoutCheck(private val settings: SystemSettings) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2002",
        category = Category.ACCESS_CONTROL,
        title = "Screen timeout",
        severity = Severity.NOTICE,
        explanation = "The phone locks itself only after the screen turns off. A long timeout leaves an " +
            "unlocked phone open to anyone nearby, for example on a desk or table.",
        remediation = Remediation(
            text = "Set Screen timeout to 1 minute or less (Settings › Display).",
            settingsActions = listOf(SettingsActions.DISPLAY),
        ),
        failsWhen = "the screen stays on for more than 2 minutes",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val timeout = settings.system(SCREEN_OFF_TIMEOUT)
        val evidence = listOf(timeout.settingEvidence("$SCREEN_OFF_TIMEOUT (ms)"))
        return timeout.evaluate("Screen timeout", evidence) { raw ->
            val millis = raw?.trim()?.toLongOrNull()
                ?: return@evaluate Outcome.unknown("Unrecognized screen timeout \"${raw ?: NOT_SET}\"", evidence)
            when {
                millis <= 0 || millis >= NEVER_MILLIS -> Outcome.fail("Screen never turns off by itself", evidence)
                millis <= MAX_MILLIS -> Outcome.pass("Screen turns off after ${describe(millis)}", evidence)
                else -> Outcome.fail("Screen stays on for ${describe(millis)}", evidence)
            }
        }
    }

    private fun describe(millis: Long): String =
        if (millis >= MINUTE && millis % MINUTE == 0L) {
            count((millis / MINUTE).toInt(), "minute")
        } else {
            count((millis / SECOND).toInt(), "second")
        }

    companion object {
        /** `Settings.System.SCREEN_OFF_TIMEOUT` */
        const val SCREEN_OFF_TIMEOUT = "screen_off_timeout"

        /** Up to two minutes passes; the usual hardening advice is one minute or less. */
        const val MAX_MILLIS = 120_000L

        private const val SECOND = 1_000L
        private const val MINUTE = 60_000L

        /** Some ROMs store "never" as Int.MAX_VALUE. */
        private const val NEVER_MILLIS = Int.MAX_VALUE.toLong()
    }
}
