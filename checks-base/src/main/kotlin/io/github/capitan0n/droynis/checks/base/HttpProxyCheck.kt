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

class HttpProxyCheck(private val network: NetworkProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3007",
        category = Category.NETWORK,
        title = "HTTP proxy",
        severity = Severity.WARNING,
        explanation = "An HTTP proxy receives the web traffic of every app that honours it. A proxy you did " +
            "not set up yourself, added by an app, a management profile or a network, can log the sites you " +
            "visit and tamper with unencrypted pages.",
        remediation = Remediation(
            text = "If you do not recognise the proxy, remove it: open the Wi-Fi network's details and set " +
                "Proxy to None.",
            settingsActions = listOf(SettingsActions.WIFI),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val snapshot = network.activeNetwork()
        val evidence = networkEvidence(snapshot)
        return snapshot.evaluate("Network state", evidence) { net ->
            when {
                net == null -> Outcome.unknown("No active network to inspect", evidence)
                net.httpProxy == null -> Outcome.pass("No HTTP proxy is set", evidence)
                else -> Outcome.fail("Web traffic goes through the proxy ${net.httpProxy}", evidence)
            }
        }
    }
}
