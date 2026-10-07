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
import io.github.capitan0n.droynis.core.toEvidence

class HttpProxyCheck(private val network: NetworkProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3007",
        category = Category.NETWORK,
        title = "HTTP proxy",
        severity = Severity.WARNING,
        explanation = "An HTTP proxy receives the web traffic of every app that honours it. A proxy you did " +
            "not set up yourself, added by an app, a management profile, a Wi-Fi network or a mobile data " +
            "access point (APN), can log the sites you visit and tamper with unencrypted pages. Droynis looks " +
            "at Wi-Fi and at mobile data, which stays connected next to Wi-Fi on most phones.",
        remediation = Remediation(
            text = "If you do not recognise the proxy, remove it. For Wi-Fi, open the network's details and set " +
                "Proxy to None. For mobile data, open Access point names (under Mobile network), pick the one in " +
                "use and clear Proxy and Port, or reset to default. An operator's own APN proxy is expected, but it " +
                "still sees your unencrypted traffic.",
            settingsActions = listOf(SettingsActions.NETWORK, SettingsActions.WIFI),
        ),
        failsWhen = "web traffic on Wi-Fi, mobile data or another network goes through an HTTP proxy",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val active = network.activeNetwork()
        val all = network.allNetworks()
        val default = (active as? Reading.Value)?.value
        val networks = (all as? Reading.Value)?.value
        val evidence = networkEvidence(active) + proxyEvidence(all)

        if (active !is Reading.Value && networks == null) {
            return Outcome.unknown("Network state could not be read", evidence)
        }
        // Each network's own proxy, plus a global proxy: Android reports it as the default network's.
        val proxies = linkedMapOf<String, String>()
        if (networks != null) {
            networks.forEach { net -> net.httpProxy?.let { proxies.putIfAbsent(where(net), it) } }
            val own = networks.firstOrNull { it.sameNetwork(default) }?.httpProxy
            default?.httpProxy?.takeIf { it != own }?.let { proxies["every network (a global proxy)"] = it }
        } else {
            default?.let { net -> net.httpProxy?.let { proxies[where(net)] = it } }
        }
        val inspected = (listOfNotNull(default) + networks.orEmpty()).map(::where).distinct()
        return when {
            proxies.isNotEmpty() -> Outcome.fail(
                proxies.entries.joinToString("; ") { (where, proxy) -> "Web traffic on $where goes through the proxy $proxy" },
                evidence,
            )
            inspected.isEmpty() -> Outcome.unknown("No active network to inspect", evidence)
            else -> Outcome.pass("No HTTP proxy is set on ${inspected.joinNames()}", evidence)
        }
    }

    private fun proxyEvidence(all: Reading<List<NetworkSnapshot>>): List<Evidence> {
        val networks = (all as? Reading.Value)?.value ?: return listOf(all.toEvidence("Other networks"))
        return networks.map { net ->
            Evidence("Proxy on ${where(net)}${net.interfaceName?.let { " ($it)" } ?: ""}", net.httpProxy ?: "none", all.source)
        } + if (networks.none { Transport.CELLULAR in it.transports }) {
            listOf(Evidence("Mobile data", "not connected", all.source, note = "its proxy is checked whenever it is connected"))
        } else {
            emptyList()
        }
    }

    private fun NetworkSnapshot.sameNetwork(other: NetworkSnapshot?): Boolean =
        other != null && interfaceName == other.interfaceName && transports == other.transports

    companion object {
        /** How Settings names a network: "Wi-Fi", "mobile data", … */
        internal fun where(net: NetworkSnapshot): String = when {
            Transport.VPN in net.transports -> "the VPN"
            Transport.WIFI in net.transports -> "Wi-Fi"
            Transport.CELLULAR in net.transports -> "mobile data"
            Transport.ETHERNET in net.transports -> "Ethernet"
            Transport.BLUETOOTH in net.transports -> "Bluetooth tethering"
            else -> "another network"
        }
    }
}
