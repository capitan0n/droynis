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

class VpnCheck(private val network: NetworkProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3002",
        category = Category.NETWORK,
        title = "VPN",
        severity = Severity.INFO,
        explanation = "A VPN encrypts traffic between this phone and the VPN server, hiding it from the " +
            "local network and the carrier. It moves that trust to the VPN provider, so pick one with an " +
            "audited no-logs policy, or host your own.",
        remediation = Remediation(
            text = "Use a trustworthy VPN, especially on public Wi-Fi. Under Settings › Network & internet " +
                "› VPN you can also turn on \"Always-on VPN\" and \"Block connections without VPN\".",
            settingsActions = listOf(SettingsActions.VPN),
        ),
        failsWhen = "no VPN is active",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val snapshot = network.activeNetwork()
        val evidence = networkEvidence(snapshot)
        return snapshot.evaluate("Network state", evidence) { net ->
            when {
                net == null -> Outcome.unknown("No active network to inspect", evidence)
                net.usesVpn -> Outcome.pass("Traffic goes through a VPN", evidence)
                else -> Outcome.fail("No VPN is active", evidence)
            }
        }
    }
}
