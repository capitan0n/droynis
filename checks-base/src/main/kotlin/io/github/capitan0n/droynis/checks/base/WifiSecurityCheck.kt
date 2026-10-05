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

class WifiSecurityCheck(private val network: NetworkProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3005",
        category = Category.NETWORK,
        title = "Wi-Fi security",
        severity = Severity.WARNING,
        explanation = "On an open or WEP Wi-Fi network anyone in range can record the traffic and set up a " +
            "look-alike network. HTTPS still protects page contents, but plain DNS lookups and badly " +
            "written apps leak.",
        remediation = Remediation(
            text = "Avoid open and WEP networks or use a VPN on them, and forget saved open networks so the " +
                "phone does not rejoin them by itself.",
            settingsActions = listOf(SettingsActions.WIFI),
        ),
        // The security type of the connected network is public API from Android 12.
        minSdk = 31,
        failsWhen = "the phone is on an open or WEP Wi-Fi network without a VPN",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val snapshot = network.activeNetwork()
        val evidence = networkEvidence(snapshot)
        return snapshot.evaluate("Network state", evidence) { net ->
            when {
                net == null -> Outcome.unknown("No active network to inspect", evidence)
                net.usesVpn -> Outcome.pass("Traffic goes through a VPN, whatever the Wi-Fi", evidence)
                Transport.WIFI !in net.transports -> Outcome.unsupported("Not connected to Wi-Fi right now", evidence)
                else -> when (val security = net.wifiSecurity) {
                    null, WifiSecurity.UNKNOWN ->
                        Outcome.unknown("The platform did not report the Wi-Fi security type", evidence)
                    WifiSecurity.OPEN -> Outcome.fail("Connected to an open Wi-Fi network without encryption", evidence)
                    WifiSecurity.WEP -> Outcome.fail("Connected to a Wi-Fi network with broken WEP encryption", evidence)
                    WifiSecurity.OWE -> Outcome.pass("Wi-Fi is encrypted (Enhanced Open), though anyone may join", evidence)
                    else -> Outcome.pass("Wi-Fi is encrypted: ${security.label}", evidence)
                }
            }
        }
    }
}
