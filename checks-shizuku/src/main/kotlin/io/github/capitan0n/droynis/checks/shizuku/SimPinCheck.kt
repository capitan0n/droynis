package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.CellularProbe
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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Whether each SIM in use asks for its PIN. Android shows this only to the system, the shell user and
 * root (`TelephonyManager.isIccLockEnabled`, Android 11+), so the check needs Shizuku or root.
 */
class SimPinCheck(private val cellular: CellularProbe) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2201",
        category = Category.ACCESS_CONTROL,
        title = "SIM card PIN",
        severity = Severity.NOTICE,
        explanation = "Without a SIM PIN, whoever takes the SIM out of a lost or stolen phone can put it in " +
            "another phone and receive your calls and texts, including the one-time codes that reset bank and " +
            "email passwords. With the PIN on, the SIM stays locked after every restart until the PIN is " +
            "entered. Most operators ship SIMs with a PIN, but it is easy to turn off.",
        remediation = Remediation(
            text = "Turn on the SIM card lock (Settings › Security › SIM card lock, or Security & privacy › More " +
                "security settings; the place varies by vendor) and change the PIN from the one printed on the " +
                "SIM's card. Keep the PUK code somewhere safe: three wrong PINs lock the SIM until it is entered.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        minSdk = 30,
        requires = setOf(Grant.SHIZUKU),
        timeout = 20.seconds,
        failsWhen = "a SIM in use has its PIN turned off",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val sims = cellular.sims()
        val simEvidence = sims.toEvidence("SIMs in use") { list ->
            if (list.isEmpty()) "none" else list.joinToString { it.label }
        }
        if (sims is Reading.Unsupported) return Outcome.unsupported("This device has no mobile network", listOf(simEvidence))
        val inUse = (sims as? Reading.Value)?.value
        if (inUse != null && inUse.isEmpty()) return Outcome.unsupported("No SIM card is in use", listOf(simEvidence))

        val read = cellular.privileged()
        if (read !is Reading.Value) {
            return Outcome.unknown("The SIM lock could not be read", listOf(simEvidence, read.toEvidence("SIM lock")))
        }
        val wanted = inUse?.mapNotNull { it.subId }?.toSet()
        val active = read.value.filter { wanted.isNullOrEmpty() || it.subId in wanted }
        if (active.isEmpty()) return Outcome.unknown("The privileged read found no active SIM", listOf(simEvidence))

        val evidence = listOf(simEvidence) + active.map { sim ->
            Evidence(
                "${sim.label} PIN",
                when (sim.pinLocked) {
                    true -> "on"
                    false -> "off"
                    null -> null
                },
                read.source,
                note = if (sim.pinLocked == null) "not readable" else null,
            )
        }
        val open = active.filter { it.pinLocked == false }
        return when {
            open.isNotEmpty() -> Outcome.fail(
                "${open.joinToString { it.label }} ${if (open.size == 1) "has" else "have"} no PIN: taken out, " +
                    "${if (open.size == 1) "it works" else "they work"} in any other phone",
                evidence,
            )
            active.all { it.pinLocked == true } -> Outcome.pass("Every SIM in use asks for its PIN after a restart", evidence)
            else -> Outcome.unknown("The SIM lock could not be read for every SIM", evidence)
        }
    }
}
