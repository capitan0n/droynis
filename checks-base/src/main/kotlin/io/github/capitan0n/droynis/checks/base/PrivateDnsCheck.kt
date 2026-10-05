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

class PrivateDnsCheck(private val network: NetworkProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3001",
        category = Category.NETWORK,
        title = "Private DNS",
        severity = Severity.WARNING,
        explanation = "Without Private DNS, every website and app domain you look up is sent in plain text. " +
            "The Wi-Fi owner or the mobile carrier can log those lookups or answer them with fake ones. " +
            "Private DNS (DNS over TLS) encrypts them.",
        remediation = Remediation(
            text = "Open Private DNS (Settings › Network & internet; the location varies by vendor), choose " +
                "\"Private DNS provider hostname\" and enter a privacy-respecting resolver such as " +
                "dns.quad9.net.",
            settingsActions = listOf(SettingsActions.NETWORK),
        ),
        minSdk = 28,
    )

    override suspend fun run(context: ScanContext): Outcome {
        val snapshot = network.activeNetwork()
        val evidence = networkEvidence(snapshot)
        return snapshot.evaluate("Network state", evidence) { net ->
            when {
                net == null -> Outcome.unknown("No active network to inspect", evidence)
                net.usesVpn -> Outcome.pass("DNS goes through the VPN tunnel", evidence)
                net.privateDnsActive == null -> Outcome.unknown("The platform did not report Private DNS", evidence)
                net.privateDnsActive && net.privateDnsServer != null ->
                    Outcome.pass("Private DNS is active: ${net.privateDnsServer}", evidence)
                net.privateDnsActive -> Outcome.pass("Private DNS is active (automatic mode)", evidence)
                else -> Outcome.fail("DNS lookups are not encrypted", evidence)
            }
        }
    }
}

/** The network facts every network check shows, so their evidence reads the same. */
internal fun networkEvidence(snapshot: Reading<NetworkSnapshot?>): List<Evidence> {
    val net = (snapshot as? Reading.Value)?.value
        ?: return listOf(snapshot.toEvidence("Active network") { "none (offline)" })
    val source = snapshot.source
    return listOf(
        Evidence("Transports", net.transports.joinToString { it.name }.ifEmpty { "unknown" }, source),
        Evidence("Private DNS active", net.privateDnsActive?.toString() ?: "not reported", source),
        Evidence("Private DNS server", net.privateDnsServer ?: "none (off or automatic)", source),
        Evidence("DNS servers", net.dnsServers.joinToString().ifEmpty { "none reported" }, source),
    ) + if (Transport.WIFI in net.transports) {
        listOf(Evidence("Wi-Fi security", net.wifiSecurity?.label ?: "not reported", source))
    } else {
        emptyList()
    }
}
