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
import io.github.capitan0n.droynis.core.toEvidence

class NfcCheck(private val radios: RadioProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3006",
        category = Category.NETWORK,
        title = "NFC",
        severity = Severity.INFO,
        explanation = "NFC talks to cards, payment terminals and tags held a few centimeters away. The short " +
            "range makes attacks rare, but switching it off when you do not pay by phone closes one more " +
            "way in.",
        remediation = Remediation(
            text = "Turn NFC off if you do not use contactless payments, transit cards or NFC tags.",
            settingsActions = listOf(SettingsActions.NFC),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = radios.nfcEnabled()
        val evidence = listOf(enabled.toEvidence("NFC enabled"))
        return enabled.evaluate("NFC", evidence) { on ->
            if (on) Outcome.fail("NFC is on", evidence) else Outcome.pass("NFC is off", evidence)
        }
    }
}
