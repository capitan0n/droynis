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

class SecureNfcCheck(private val radios: RadioProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3011",
        category = Category.NETWORK,
        title = "Secure NFC",
        severity = Severity.NOTICE,
        explanation = "With NFC on, a locked phone still answers card readers held close to it: transit " +
            "cards and some payment apps work without unlocking. Requiring an unlock for NFC (Secure NFC) " +
            "keeps payments and transit cards for when the phone is unlocked, so someone who holds a reader " +
            "to your pocket, or takes the phone, can't use them.",
        remediation = Remediation(
            text = "Open Settings › Connected devices › Connection preferences › NFC and turn on \"Require " +
                "device unlock for NFC\" (\"Secure NFC\" on older Android). If you don't use NFC, turn it off.",
            settingsActions = listOf(SettingsActions.NFC),
        ),
        // NfcAdapter.isSecureNfcSupported() and isSecureNfcEnabled() arrived in Android 10.
        minSdk = 29,
        failsWhen = "NFC is on and works while the phone is locked",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = radios.nfcEnabled()
        val secure = radios.secureNfcEnabled()
        val evidence = listOf(
            enabled.toEvidence("NFC enabled"),
            secure.toEvidence("Requires unlock for NFC"),
        )
        return enabled.evaluate("NFC", evidence) { on ->
            if (!on) return@evaluate Outcome.pass("NFC is off", evidence)
            secure.evaluate("The Secure NFC setting", evidence) { required ->
                if (required) {
                    Outcome.pass("NFC works only while the phone is unlocked", evidence)
                } else {
                    Outcome.fail("NFC is on and works while the phone is locked", evidence)
                }
            }
        }
    }
}
