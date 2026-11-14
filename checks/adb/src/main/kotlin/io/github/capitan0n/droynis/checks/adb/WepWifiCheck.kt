package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
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
 * Saved networks that use WEP, read from the same `dumpsys wifi` section as [OpenWifiCheck] by
 * [SavedNetworksDump]: an enabled security type 1 (`WifiConfiguration.SECURITY_TYPE_WEP`).
 *
 * NETW-3102 counts a WEP network only while it joins by itself; this one counts it either way,
 * because the weakness is in the encryption, not in who starts the connection. WPA with TKIP is
 * just as dated, but a saved network doesn't say which cipher its access point uses: WPA and WPA2
 * share one security type (2, PSK), and the cipher lists in the dump are what the phone would
 * accept, not what the network offers. So TKIP is not judged here.
 */
class WepWifiCheck(private val dumpsys: Dumpsys) : Check {

    override val spec = CheckSpec(
        id = "NETW-3105",
        category = Category.NETWORK,
        title = "Saved Wi-Fi networks with broken encryption",
        severity = Severity.NOTICE,
        explanation = "WEP, the Wi-Fi encryption of the early 2000s, can be broken in minutes with free " +
            "tools: anyone in range can recover the key, read the traffic and join the network. A saved " +
            "WEP network is as exposed as an open one, whether the phone joins it by itself or you tap " +
            "it. Droynis can't tell WPA with the outdated TKIP cipher from WPA2: saved networks don't " +
            "record it. Android keeps the saved networks in its Wi-Fi service, which only the ADB, " +
            "Shizuku or root tier can read.",
        remediation = Remediation(
            text = "If the network is yours, switch the router to WPA2 or WPA3, or replace a router that " +
                "offers neither, then forget the network on the phone and join it again. Forget WEP " +
                "networks you don't run: Settings › Network & internet › Internet (or Wi-Fi) › Saved " +
                "networks. If you must use one, use a VPN on it.",
            settingsActions = listOf(SettingsActions.WIFI_SAVED_NETWORKS, SettingsActions.WIFI),
        ),
        // Read with OpenWifiCheck's parser, which needs the security parameters list of Android 12.
        minSdk = 31,
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "a saved Wi-Fi network uses WEP",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = dumpsys.dump(WifiMacCheck.SERVICE)
        if (dump !is Reading.Value) {
            return Outcome.unknown("The Wi-Fi service could not be read", listOf(dump.toEvidence("Wi-Fi service")))
        }
        val networks = when (val result = SavedNetworksDump.parse(dump.value)) {
            is SavedNetworksDump.Result.Failed -> return Outcome.unknown(
                "The Wi-Fi service's output is in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("Wi-Fi service", null, dump.source, note = result.reason)),
            )
            is SavedNetworksDump.Result.Parsed -> result.networks
        }
        // Networks apps added for now are not the user's saved networks, as in OpenWifiCheck.
        val saved = networks.filterNot { it.ephemeral }
        val wep = saved.filter { SavedNetworksDump.TYPE_WEP in it.securityTypes }

        val evidence = buildList {
            add(Evidence("Saved Wi-Fi networks", saved.size.toString(), dump.source))
            add(Evidence("Using WEP", wep.size.toString(), dump.source))
            // A network's name can say where you live, work or travel.
            wep.forEach {
                val note = if (it.autojoin) "joins automatically" else "doesn't join automatically"
                add(Evidence("WEP network", it.ssid, dump.source, note = note, personal = true))
            }
        }
        if (wep.isNotEmpty()) {
            val n = wep.size
            return Outcome.fail(
                "${count(n, "saved Wi-Fi network uses", "saved Wi-Fi networks use")} WEP: ${wep.map { it.ssid }.joinNames()}",
                evidence,
            )
        }
        return if (saved.isEmpty()) {
            Outcome.pass("No saved Wi-Fi networks", evidence)
        } else {
            Outcome.pass("No saved Wi-Fi network uses WEP", evidence)
        }
    }
}
