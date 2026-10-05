package io.github.capitan0n.droynis.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.Uri
import android.net.wifi.WifiInfo
import android.os.Build
import io.github.capitan0n.droynis.checks.base.NetworkProbe
import io.github.capitan0n.droynis.checks.base.NetworkSnapshot
import io.github.capitan0n.droynis.checks.base.Transport
import io.github.capitan0n.droynis.checks.base.WifiSecurity
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** Reads the default network's state. Needs only ACCESS_NETWORK_STATE; no internet access. */
internal class AndroidNetwork(private val context: Context) : NetworkProbe {

    override fun activeNetwork(): Reading<NetworkSnapshot?> {
        val source = Source("ConnectivityManager.getActiveNetwork() + LinkProperties")
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: return Reading.Unsupported("no ConnectivityManager service", source)
        return probe(source) {
            val network = connectivity.activeNetwork ?: return@probe Reading.Value(null, source)
            Reading.Value(
                snapshot(
                    connectivity.getNetworkCapabilities(network),
                    connectivity.getLinkProperties(network),
                    // The default proxy covers both a global proxy and the network's own.
                    connectivity.defaultProxy,
                ),
                source,
            )
        }
    }

    private fun snapshot(capabilities: NetworkCapabilities?, link: LinkProperties?, proxy: ProxyInfo?): NetworkSnapshot {
        val transports = buildSet {
            if (capabilities != null) {
                TRANSPORTS.forEach { (code, transport) -> if (capabilities.hasTransport(code)) add(transport) }
            }
            if (isEmpty()) add(Transport.OTHER)
        }
        return NetworkSnapshot(
            transports = transports,
            validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
            metered = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false,
            privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) link?.isPrivateDnsActive else null,
            privateDnsServer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) link?.privateDnsServerName else null,
            dnsServers = link?.dnsServers.orEmpty().mapNotNull { it.hostAddress },
            interfaceName = link?.interfaceName,
            wifiSecurity = wifiSecurity(capabilities),
            addresses = link?.linkAddresses.orEmpty().map { it.toString() },
            httpProxy = (proxy ?: link?.httpProxy)?.let { describe(it) },
        )
    }

    /** "host:port", or the PAC script URL for an automatic proxy. */
    private fun describe(proxy: ProxyInfo): String? =
        proxy.pacFileUrl?.takeIf { it != Uri.EMPTY }?.toString() ?: proxy.host?.let { "$it:${proxy.port}" }

    /**
     * The connected Wi-Fi's security type. Without location permission Android 12+ redacts the
     * SSID and BSSID in this WifiInfo, but not the security type.
     */
    private fun wifiSecurity(capabilities: NetworkCapabilities?): WifiSecurity? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        val info = capabilities?.transportInfo as? WifiInfo ?: return null
        return when (info.currentSecurityType) {
            WifiInfo.SECURITY_TYPE_OPEN -> WifiSecurity.OPEN
            WifiInfo.SECURITY_TYPE_WEP -> WifiSecurity.WEP
            WifiInfo.SECURITY_TYPE_PSK -> WifiSecurity.WPA_PERSONAL
            WifiInfo.SECURITY_TYPE_SAE -> WifiSecurity.WPA3_PERSONAL
            WifiInfo.SECURITY_TYPE_EAP,
            WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE,
            WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT,
            -> WifiSecurity.ENTERPRISE
            WifiInfo.SECURITY_TYPE_OWE -> WifiSecurity.OWE
            WifiInfo.SECURITY_TYPE_WAPI_PSK, WifiInfo.SECURITY_TYPE_WAPI_CERT -> WifiSecurity.WAPI
            WifiInfo.SECURITY_TYPE_PASSPOINT_R1_R2, WifiInfo.SECURITY_TYPE_PASSPOINT_R3 -> WifiSecurity.PASSPOINT
            WifiInfo.SECURITY_TYPE_DPP -> WifiSecurity.DPP
            WifiInfo.SECURITY_TYPE_OSEN -> WifiSecurity.OTHER
            else -> WifiSecurity.UNKNOWN
        }
    }

    private companion object {
        val TRANSPORTS = listOf(
            NetworkCapabilities.TRANSPORT_WIFI to Transport.WIFI,
            NetworkCapabilities.TRANSPORT_CELLULAR to Transport.CELLULAR,
            NetworkCapabilities.TRANSPORT_ETHERNET to Transport.ETHERNET,
            NetworkCapabilities.TRANSPORT_VPN to Transport.VPN,
            NetworkCapabilities.TRANSPORT_BLUETOOTH to Transport.BLUETOOTH,
        )
    }
}
