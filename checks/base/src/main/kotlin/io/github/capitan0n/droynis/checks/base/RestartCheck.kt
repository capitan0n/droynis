package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class RestartCheck(private val uptime: UptimeProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1080",
        category = Category.DEVICE_INTEGRITY,
        title = "Time since restart",
        severity = Severity.NOTICE,
        explanation = "After a restart, Android keeps the keys to your files out of memory until you first " +
            "unlock the phone: the state phone-cracking tools find hardest. From then on the keys stay in " +
            "memory, even while the screen is locked, until the next restart. A restart also removes spyware " +
            "that lives only in memory, as many zero-click exploits do, and finishes updates that wait for " +
            "one. The NSA's mobile device guidance advises restarting once a week.",
        remediation = Remediation(
            text = "Restart the phone: hold the power button (with volume up on some phones) and tap Restart. " +
                "Once a week is enough. GrapheneOS can also restart by itself after the phone stays locked " +
                "for a while (Auto reboot).",
        ),
        failsWhen = "the phone hasn't restarted for more than 7 days",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val reading = uptime.sinceBoot()
        val evidence = listOf(reading.toEvidence("Time since restart") { roughly(it) })
        return reading.evaluate("The time since the last restart", evidence) { up ->
            when {
                up.isNegative() -> Outcome.unknown("The time since the last restart is not plausible ($up)", evidence)
                up > LIMIT -> Outcome.fail("The phone hasn't restarted for ${roughly(up)}", evidence)
                else -> Outcome.pass("The phone restarted ${roughly(up)} ago", evidence)
            }
        }
    }

    companion object {
        val LIMIT: Duration = 7.days
    }
}
