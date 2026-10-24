package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.DevicePolicy
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
 * Reads each saved network's security types and auto-connect switch from `dumpsys wifi`, checked
 * against `WifiConfiguration.toString()` in Android 12L, 13, 14, 15, 16 and 17:
 *
 * ```
 * WifiConfigManager - Configured networks Begin ----
 * ID: 3 SSID: "Cafe" PROVIDER-NAME: null BSSID: null FQDN: null …
 *  …
 *  not-shared trusted
 *  macRandomizationSetting: 3
 *  …
 * SecurityParams List:
 * Security Parameters:
 *  Type: 0
 *  Enabled: true
 *  …
 * Enterprise config:
 * …
 *  cuid=1000 cname=com.android.settings lcuid=1000 allowAutojoin=true mAllowedAutoJoinInAdvancedProtection=false …
 * WifiConfigManager - Configured networks End ----
 * ```
 *
 * Each network is one block from its `ID:` line to the next. Free text (network names, an
 * enterprise identity, a proxy) sits on the header, `connect choice` and `linked` lines and in the
 * enterprise and IP sections; each field is taken from outside those or must appear exactly once,
 * so a crafted name can only make the parse fail. A name with a line break breaks its own header,
 * which [WifiDump] and this parser both refuse.
 */
object SavedNetworksDump {

    /** `WifiConfiguration.SECURITY_TYPE_*` that let anyone run a network with that name. */
    const val TYPE_OPEN = 0
    const val TYPE_WEP = 1
    const val TYPE_OWE = 6

    data class SavedNetwork(
        val networkId: Int,
        val ssid: String,
        /** Security types the network may connect with right now (`SecurityParams` that are enabled). */
        val securityTypes: Set<Int>,
        /** The user's "Automatically connect" switch (`allowAutojoin`). */
        val autojoin: Boolean,
        /** Added by an app or the system for now, not saved by the user; Android never auto-joins these as saved networks. */
        val ephemeral: Boolean,
        /** Android 17: false keeps the network from auto-joining while Advanced Protection is on; null where not printed. */
        val autojoinWithAdvancedProtection: Boolean? = null,
    ) {
        /** No password proves who runs it: open, Enhanced Open (OWE) or WEP. */
        val insecure: Boolean get() = securityTypes.any { it in INSECURE }
    }

    sealed interface Result {
        data class Parsed(val networks: List<SavedNetwork>) : Result

        data class Failed(val reason: String) : Result
    }

    private val INSECURE = setOf(TYPE_OPEN, TYPE_WEP, TYPE_OWE)
    private const val LIST = "SecurityParams List:"
    private const val ENTERPRISE = "Enterprise config:"
    private val TYPE = Regex("""^\s*Type: (\d+)$""")
    private val ENABLED = Regex("""^\s*Enabled: (true|false)$""")
    private val AUTOJOIN = Regex("""(?:^|\s)allowAutojoin=(true|false)(?=\s|$)""")
    private val AUTOJOIN_AAPM = Regex("""(?:^|\s)mAllowedAutoJoinInAdvancedProtection=(true|false)(?=\s|$)""")
    private val NOT_USER_SAVED = setOf("ephemeral", "fromWifiNetworkSuggestion", "fromWifiNetworkSpecifier")
    private val FREE_TEXT_LINE = Regex("""^\s*(?:connect choice:|linked:)""")

    fun parse(text: String): Result {
        val lines = text.lines().map { it.trimEnd() }
        lines.firstOrNull { it.startsWith(WifiDump.NOT_STARTED) }?.let { return Result.Failed(it.trim()) }
        val begin = lines.indexOfFirst { it.trim() == WifiDump.SAVED_BEGIN }
        if (begin < 0) return Result.Failed("no saved-network section in the output")
        val end = lines.indexOfFirst { it.trim() == WifiDump.SAVED_END }
        if (end < begin) return Result.Failed("the saved-network section does not end")

        val networks = mutableListOf<SavedNetwork>()
        var header: MatchResult? = null
        val body = mutableListOf<String>()
        for (line in lines.subList(begin + 1, end) + null) {
            val next = line?.let { WifiDump.HEADER.find(it) }
            if (line != null && next == null) {
                // Nothing but networks belongs here: text before the first one is a name that broke its own header.
                if (header == null && line.isNotBlank()) return Result.Failed("text before the first saved network: ${WifiDump.quote(line)}")
                body += line
                continue
            }
            header?.let { head ->
                when (val network = block(head, body)) {
                    is Block.Done -> networks += network.network
                    is Block.Bad -> return Result.Failed(network.reason)
                }
            }
            header = next
            body.clear()
        }
        return Result.Parsed(networks)
    }

    private sealed interface Block {
        data class Done(val network: SavedNetwork) : Block

        data class Bad(val reason: String) : Block
    }

    private fun block(head: MatchResult, body: List<String>): Block {
        val id = head.groupValues[1].toInt()
        val ssid = WifiDump.unquote(head.groupValues[2])
        fun bad(reason: String) = Block.Bad("saved network $id $reason")

        val lists = body.indices.filter { body[it].trim() == LIST }
        if (lists.size != 1) return bad(if (lists.isEmpty()) "has no security parameters" else "lists its security parameters twice")
        val list = lists.single()
        val enterprise = (list + 1 until body.size).firstOrNull { body[it].trim() == ENTERPRISE }
            ?: return bad("has no enterprise section after its security parameters")

        // Flags print as bare words between the header and the security list.
        val flags = body.subList(0, list).filterNot { FREE_TEXT_LINE.containsMatchIn(it) }
            .flatMap { it.trim().split(Regex("\\s+")) }.toSet()

        val types = mutableSetOf<Int>()
        val params = body.subList(list + 1, enterprise)
        for ((i, line) in params.withIndex()) {
            val type = TYPE.matchEntire(line)?.groupValues?.get(1)?.toIntOrNull() ?: continue
            val enabled = params.getOrNull(i + 1)?.let { ENABLED.matchEntire(it) }?.groupValues?.get(1)
                ?: return bad("has a security type without its state: ${WifiDump.quote(line)}")
            if (enabled == "true") types += type
        }
        if (params.none { TYPE.matches(it) }) return bad("lists no security type")

        val tail = body.subList(enterprise + 1, body.size)
        val autojoin = tail.flatMap { line -> AUTOJOIN.findAll(line).map { it.groupValues[1] }.toList() }
        if (autojoin.size != 1) return bad(if (autojoin.isEmpty()) "has no auto-connect setting" else "has its auto-connect setting twice")
        val aapm = tail.flatMap { line -> AUTOJOIN_AAPM.findAll(line).map { it.groupValues[1] }.toList() }
        if (aapm.size > 1) return bad("has its Advanced Protection auto-connect setting twice")

        return Block.Done(
            SavedNetwork(
                networkId = id,
                ssid = ssid,
                securityTypes = types,
                autojoin = autojoin.single() == "true",
                ephemeral = flags.any { it in NOT_USER_SAVED },
                autojoinWithAdvancedProtection = aapm.singleOrNull()?.toBooleanStrict(),
            ),
        )
    }
}

class OpenWifiCheck(
    private val dumpsys: Dumpsys,
    private val policy: DevicePolicy,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3102",
        category = Category.NETWORK,
        title = "Open Wi-Fi networks that join automatically",
        severity = Severity.NOTICE,
        explanation = "A network without a password, open, Enhanced Open or WEP, proves nothing about who " +
            "runs it: anyone can set up one with the same name, and a phone that joins it by itself hands " +
            "that person its traffic, DNS and sign-in pages. Enhanced Open encrypts the radio link, but not " +
            "against whoever runs the access point. Android keeps the saved networks in its Wi-Fi service, " +
            "which only the ADB, Shizuku or root tier can read.",
        remediation = Remediation(
            text = "Open Settings › Network & internet › Internet (or Wi-Fi) › Saved networks, tap each network " +
                "listed and turn off \"Automatically connect\", or forget it. Join such networks by hand, " +
                "with a VPN.",
            settingsActions = listOf(SettingsActions.WIFI),
        ),
        // The per-network security parameters list in dumpsys arrived in Android 12.
        minSdk = 31,
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "a saved open, Enhanced Open or WEP network joins automatically",
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
        val saved = networks.filterNot { it.ephemeral }
        val autojoining = saved.filter { it.insecure && it.autojoin }
        // Android 17 skips these while Advanced Protection is on; only a positive reading counts.
        val protection = if (autojoining.any { it.autojoinWithAdvancedProtection == false }) policy.advancedProtection() else null
        val heldBack = if ((protection as? Reading.Value)?.value == true) {
            autojoining.filter { it.autojoinWithAdvancedProtection == false }
        } else {
            emptyList()
        }
        val counted = autojoining - heldBack.toSet()

        val evidence = buildList {
            add(Evidence("Saved Wi-Fi networks", saved.size.toString(), dump.source))
            add(Evidence("Without a password", saved.count { it.insecure }.toString(), dump.source))
            protection?.let { add(it.toEvidence("Advanced Protection")) }
            // A network's name can say where you live, work or travel.
            counted.forEach { add(Evidence("Joins automatically", it.ssid, dump.source, note = kind(it), personal = true)) }
            heldBack.forEach {
                add(Evidence("Kept from joining by Advanced Protection", it.ssid, dump.source, note = kind(it), personal = true))
            }
        }
        if (counted.isNotEmpty()) {
            val n = counted.size
            return Outcome.fail(
                "${count(n, "saved Wi-Fi network")} without a password ${if (n == 1) "joins" else "join"} " +
                    "automatically: ${counted.map { it.ssid }.joinNames()}",
                evidence,
            )
        }
        return when {
            saved.isEmpty() -> Outcome.pass("No saved Wi-Fi networks", evidence)
            saved.none { it.insecure } -> Outcome.pass("Every saved Wi-Fi network needs a password", evidence)
            heldBack.isNotEmpty() -> Outcome.pass(
                "Advanced Protection keeps saved Wi-Fi networks without a password from joining automatically",
                evidence,
            )
            else -> Outcome.pass("Saved Wi-Fi networks without a password don't join automatically", evidence)
        }
    }

    private fun kind(network: SavedNetworksDump.SavedNetwork): String = listOfNotNull(
        "open".takeIf { SavedNetworksDump.TYPE_OPEN in network.securityTypes },
        "Enhanced Open".takeIf { SavedNetworksDump.TYPE_OWE in network.securityTypes },
        "WEP".takeIf { SavedNetworksDump.TYPE_WEP in network.securityTypes },
    ).joinToString(" or ")
}
