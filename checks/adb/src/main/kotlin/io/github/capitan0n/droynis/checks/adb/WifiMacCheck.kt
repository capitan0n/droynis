package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.count
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
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Reads two parts of `dumpsys wifi`, checked against the Wi-Fi module in Android 17:
 *
 * ```
 * mWifiInfo SSID: "Home", BSSID: 12:34:56:78:9a:bc, MAC: da:a1:19:00:00:01, IP: …, Supplicant state: COMPLETED, …
 * WifiConfigManager - Configured networks Begin ----
 * * ID: 0 SSID: "Home" PROVIDER-NAME: null BSSID: null FQDN: null …
 *  macRandomizationSetting: 3
 * WifiConfigManager - Configured networks End ----
 * ```
 *
 * One `mWifiInfo` line per Wi-Fi interface in client mode (`ClientModeImpl`); none while Wi-Fi is
 * off. Its MAC is the address in use, never redacted in the dump. Only that MAC's kind and the
 * names of networks set to the device MAC are kept: no address, BSSID or other network.
 *
 * An SSID is at most 32 bytes, too short to hold the whole `, BSSID: …, MAC: …,` sequence (39
 * characters at least), so a network name can't fake the MAC, quoted (Android 12+) or not; the
 * fields after it up to the supplicant state are numbers. A crafted saved network's name can only
 * change the name shown, or make the parse fail.
 */
object WifiDump {

    /** What kind of address a MAC is, from its locally administered bit. */
    enum class MacKind { RANDOMIZED, DEVICE, HIDDEN }

    data class Connection(val connected: Boolean, val mac: MacKind, val networkId: Int?)

    /** `WifiConfiguration.macRandomizationSetting`: 0 is "Use device MAC". */
    data class SavedNetwork(val networkId: Int, val ssid: String, val macRandomization: Int) {
        val usesDeviceMac: Boolean get() = macRandomization == RANDOMIZATION_NONE
    }

    sealed interface Result {
        data class Parsed(val connections: List<Connection>, val saved: List<SavedNetwork>) : Result

        data class Failed(val reason: String) : Result
    }

    const val RANDOMIZATION_NONE = 0

    /** `WifiInfo.DEFAULT_MAC_ADDRESS`: what it holds before an interface reports its address. */
    private const val HIDDEN_MAC = "02:00:00:00:00:00"

    private const val INFO_PREFIX = "mWifiInfo SSID: "
    internal const val SAVED_BEGIN = "WifiConfigManager - Configured networks Begin ----"
    internal const val SAVED_END = "WifiConfigManager - Configured networks End ----"
    private const val ADDRESS = "[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
    // The MAC is never "<none>" in practice (WifiInfo starts with 02:00:00:00:00:00); allowing it
    // would let a 28-character network name fake the whole sequence where SSIDs print unquoted.
    private val ADDRESSES = Regex(""", BSSID: (<none>|$ADDRESS), MAC: ($ADDRESS), """)
    private val SUPPLICANT = Regex(""", Supplicant state: ([A-Z_0-9]+),""")
    private val NET_ID = Regex(""", Net ID: (-?\d+),""")
    internal val HEADER = Regex("""^(?:\* |- DSBLE )?ID: (-?\d+) SSID: (.*?) PROVIDER-NAME: """)
    private val SETTING = Regex("""^\s*macRandomizationSetting: (-?\d+)$""")
    private val SETTING_LIKE = Regex("""^\s*macRandomizationSetting:""")
    private const val MAX_QUOTE = 100
    internal const val NOT_STARTED = "Wifi Service is not started"

    fun parse(text: String): Result {
        val lines = text.lines().map { it.trimEnd() }
        lines.firstOrNull { it.startsWith(NOT_STARTED) }?.let { return Result.Failed(it.trim()) }

        val connections = mutableListOf<Connection>()
        for (line in lines) {
            val start = line.indexOf(INFO_PREFIX)
            if (start < 0 || line.substring(0, start).isNotBlank()) continue
            val info = line.substring(start)
            val addresses = ADDRESSES.find(info) ?: return Result.Failed("a connection line without its addresses: ${quote(info)}")
            // From the ", " that ends the match: Android 10 prints the state right after the MAC.
            val rest = info.substring(addresses.range.last - 1)
            val state = SUPPLICANT.find(rest)?.groupValues?.get(1)
                ?: return Result.Failed("a connection line without its state: ${quote(info)}")
            val mac = addresses.groupValues[2]
            connections += Connection(
                connected = state == "COMPLETED",
                mac = kindOf(mac),
                networkId = NET_ID.find(rest)?.groupValues?.get(1)?.toIntOrNull(),
            )
        }

        val begin = lines.indexOfFirst { it.trim() == SAVED_BEGIN }
        if (begin < 0) return Result.Failed("no saved-network section in the output")
        val end = lines.indexOfFirst { it.trim() == SAVED_END }
        if (end < begin) return Result.Failed("the saved-network section does not end")

        val saved = mutableListOf<SavedNetwork>()
        var header: Pair<Int, String>? = null
        var setting: Int? = null
        fun close(): String? {
            val (id, ssid) = header ?: return null
            val value = setting ?: return "saved network $id has no MAC randomization setting"
            saved += SavedNetwork(id, ssid, value)
            return null
        }
        for (line in lines.subList(begin + 1, end)) {
            val head = HEADER.find(line)
            if (head != null) {
                close()?.let { return Result.Failed(it) }
                header = head.groupValues[1].toInt() to unquote(head.groupValues[2])
                setting = null
                continue
            }
            if (!SETTING_LIKE.containsMatchIn(line)) continue
            val value = SETTING.matchEntire(line)?.groupValues?.get(1)?.toIntOrNull()
                ?: return Result.Failed("a MAC randomization line in an unknown shape: ${quote(line)}")
            // A second setting in one network means the output isn't what this parser knows.
            if (header == null || setting != null) return Result.Failed("a MAC randomization line out of place: ${quote(line)}")
            setting = value
        }
        close()?.let { return Result.Failed(it) }
        return Result.Parsed(connections, saved)
    }

    /** Random addresses set the locally administered bit; a maker's address from its IEEE block doesn't. */
    fun kindOf(mac: String): MacKind {
        if (mac.equals(HIDDEN_MAC, ignoreCase = true)) return MacKind.HIDDEN
        val first = mac.substring(0, 2).toInt(16)
        return if (first and LOCALLY_ADMINISTERED != 0) MacKind.RANDOMIZED else MacKind.DEVICE
    }

    private const val LOCALLY_ADMINISTERED = 0x02

    internal fun unquote(ssid: String): String =
        if (ssid.length >= 2 && ssid.startsWith('"') && ssid.endsWith('"')) ssid.substring(1, ssid.length - 1) else ssid

    internal fun quote(line: String) = line.trim().take(MAX_QUOTE)
}

class WifiMacCheck(private val dumpsys: Dumpsys) : Check {

    override val spec = CheckSpec(
        id = "NETW-3101",
        category = Category.NETWORK,
        title = "Wi-Fi MAC randomization",
        severity = Severity.NOTICE,
        explanation = "Every Wi-Fi network the phone joins sees its MAC address. The phone's own address " +
            "is the same everywhere, so the networks, and whoever runs several of them, can recognize the " +
            "phone and link its visits. Android uses a random address for each network unless that " +
            "network is set to use the device MAC. Android keeps this in its Wi-Fi service, which only " +
            "the ADB, Shizuku or root tier can read.",
        remediation = Remediation(
            text = "Open Settings › Network & internet › Internet (or Wi-Fi), tap the gear next to each " +
                "network listed, then Privacy, and choose \"Use randomized MAC\". Some company and carrier " +
                "networks need the device MAC; mute this check if only those are left.",
            settingsActions = listOf(SettingsActions.WIFI),
        ),
        // Per-network MAC randomization and its setting arrived in Android 10.
        minSdk = 29,
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "the current Wi-Fi connection or a saved network uses the phone's own MAC address",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = dumpsys.dump(SERVICE)
        if (dump !is Reading.Value) {
            return Outcome.unknown("The Wi-Fi service could not be read", listOf(dump.toEvidence("Wi-Fi service")))
        }
        val parsed = when (val result = WifiDump.parse(dump.value)) {
            is WifiDump.Result.Failed -> return Outcome.unknown(
                "The Wi-Fi service's output is in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("Wi-Fi service", null, dump.source, note = result.reason)),
            )
            is WifiDump.Result.Parsed -> result
        }
        val connected = parsed.connections.filter { it.connected }
        val deviceMac = parsed.saved.filter { it.usesDeviceMac }
        val evidence = evidence(connected, parsed.saved, deviceMac, dump.source)

        val current = connected.any { it.mac == WifiDump.MacKind.DEVICE }
        if (current || deviceMac.isNotEmpty()) {
            val n = deviceMac.size
            val summary = when {
                current && n > 0 -> "The current Wi-Fi connection uses the phone's own MAC address, and " +
                    "${count(n, "saved network")} ${if (n == 1) "is" else "are"} set to use it"
                // Nothing asked for it: the phone may not randomize at all.
                current -> "The current Wi-Fi connection uses the phone's own MAC address, though no saved " +
                    "network is set to: the phone may not support MAC randomization"
                else -> "${count(n, "saved Wi-Fi network")} ${if (n == 1) "uses" else "use"} the phone's own MAC address"
            }
            return Outcome.fail(summary, evidence)
        }
        return when {
            connected.isEmpty() -> Outcome.unsupported(
                "Not connected to Wi-Fi right now; no saved network is set to use the phone's own MAC address",
                evidence,
            )
            connected.any { it.mac == WifiDump.MacKind.HIDDEN } ->
                Outcome.unknown("The Wi-Fi service did not show which MAC address the connection uses", evidence)
            else -> Outcome.pass("Wi-Fi uses a randomized MAC address, and no saved network uses the phone's own", evidence)
        }
    }

    private fun evidence(
        connected: List<WifiDump.Connection>,
        saved: List<WifiDump.SavedNetwork>,
        deviceMac: List<WifiDump.SavedNetwork>,
        source: Source,
    ): List<Evidence> = buildList {
        if (connected.isEmpty()) add(Evidence("Current Wi-Fi connection", "none", source))
        connected.forEach {
            val kind = when (it.mac) {
                WifiDump.MacKind.RANDOMIZED -> "randomized MAC address"
                WifiDump.MacKind.DEVICE -> "the phone's own MAC address"
                WifiDump.MacKind.HIDDEN -> "MAC address not shown"
            }
            add(Evidence("Current Wi-Fi connection", kind, source))
        }
        add(Evidence("Saved Wi-Fi networks", saved.size.toString(), source))
        // A network's name can say where you live or work.
        deviceMac.forEach { add(Evidence("Uses the phone's own MAC address", it.ssid, source, personal = true)) }
    }

    companion object {
        const val SERVICE = "wifi"
    }
}
