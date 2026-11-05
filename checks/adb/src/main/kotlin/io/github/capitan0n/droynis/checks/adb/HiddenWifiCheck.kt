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
 * Saved hidden networks, read from the same `dumpsys wifi` section as [OpenWifiCheck] by
 * [SavedNetworksDump]: the `HIDDEN:` field on each network's header line.
 */
class HiddenWifiCheck(private val dumpsys: Dumpsys) : Check {

    override val spec = CheckSpec(
        id = "NETW-3104",
        category = Category.NETWORK,
        title = "Hidden Wi-Fi networks",
        severity = Severity.NOTICE,
        explanation = "A hidden network doesn't announce its name, so a phone that saved one calls out that " +
            "name when it looks for Wi-Fi, wherever it is. Anyone nearby can log the name to recognize and " +
            "follow the phone or learn where you live or work, and can set up an access point with the same " +
            "name to lure the phone in. Hiding a network adds no security: its name still shows in the " +
            "traffic of every device that uses it. Android keeps the saved networks in its Wi-Fi service, " +
            "which only the ADB, Shizuku or root tier can read.",
        remediation = Remediation(
            text = "On the router, make the network visible again (turn off \"Hide SSID\" or \"Hidden network\"). " +
                "Then forget the network on the phone and join it again, so Android stops calling out its name: " +
                "Settings › Network & internet › Internet (or Wi-Fi) › Saved networks. Forget hidden networks " +
                "you no longer use.",
            settingsActions = listOf(SettingsActions.WIFI_SAVED_NETWORKS, SettingsActions.WIFI),
        ),
        // Read with OpenWifiCheck's parser, which needs the security parameters list of Android 12.
        minSdk = 31,
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "a saved Wi-Fi network is hidden, so the phone calls out its name when it looks for Wi-Fi",
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
        val hidden = saved.filter { it.hidden == true }
        val unread = saved.count { it.hidden == null }

        val evidence = buildList {
            add(Evidence("Saved Wi-Fi networks", saved.size.toString(), dump.source))
            add(
                Evidence(
                    "Hidden",
                    hidden.size.toString(),
                    dump.source,
                    note = if (unread > 0) "${count(unread, "network doesn't", "networks don't")} say" else null,
                ),
            )
            // A network's name can say where you live, work or travel.
            hidden.forEach {
                val note = if (it.autojoin) "joins automatically" else "doesn't join automatically"
                add(Evidence("Hidden network", it.ssid, dump.source, note = note, personal = true))
            }
        }
        if (hidden.isNotEmpty()) {
            val n = hidden.size
            return Outcome.fail(
                "${count(n, "saved Wi-Fi network is", "saved Wi-Fi networks are")} hidden: ${hidden.map { it.ssid }.joinNames()}",
                evidence,
            )
        }
        return when {
            saved.isEmpty() -> Outcome.pass("No saved Wi-Fi networks", evidence)
            unread > 0 -> Outcome.unknown(
                "The Wi-Fi service doesn't say whether ${count(unread, "saved network is", "saved networks are")} hidden",
                evidence,
            )
            else -> Outcome.pass("No saved Wi-Fi network is hidden", evidence)
        }
    }
}
