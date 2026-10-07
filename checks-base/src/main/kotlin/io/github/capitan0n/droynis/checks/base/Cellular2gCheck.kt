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
import kotlin.time.Duration.Companion.seconds

/**
 * Whether the phone may fall back to 2G. Android 11 and older keep the network mode in a setting any
 * app may read; Android 12 added the Allow 2G switch and keeps both where only the system, the shell
 * user and root can read them, so there this check needs Shizuku or root, unless device policy has
 * turned 2G off.
 */
class Cellular2gCheck(
    private val cellular: CellularProbe,
    private val settings: SystemSettings,
    private val properties: SystemProperties,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3010",
        category = Category.NETWORK,
        title = "2G mobile networks",
        severity = Severity.NOTICE,
        explanation = "2G (GSM) never checks that a cell tower is genuine, and its encryption is weak or can be " +
            "switched off. Fake base stations (IMSI catchers and \"SMS blasters\") pull nearby phones down to 2G " +
            "to locate them, listen to calls, read texts or send scam SMS. With 2G off the phone ignores them; " +
            "where an operator still relies on 2G, coverage can suffer. Android 12 and later hide this setting " +
            "from apps, so there Droynis reads it with Shizuku or root.",
        remediation = Remediation(
            text = "On Android 12 and later turn off Allow 2G (Settings › Network & internet › SIMs, or Mobile " +
                "network; the place varies by vendor). Where there is no such switch, set Network mode to one " +
                "without 2G, such as LTE/3G or 5G/LTE. Advanced Protection turns 2G off too.",
            settingsActions = listOf(SettingsActions.MOBILE_NETWORK, SettingsActions.NETWORK),
        ),
        timeout = 20.seconds,
        failsWhen = "a SIM in use may connect to 2G networks",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val sims = cellular.sims()
        val simEvidence = sims.toEvidence("SIMs in use") { list ->
            if (list.isEmpty()) "none" else list.joinToString { it.label }
        }
        if (sims is Reading.Unsupported) return Outcome.unsupported("This device has no mobile network", listOf(simEvidence))
        val inUse = (sims as? Reading.Value)?.value
        if (inUse != null && inUse.isEmpty()) return Outcome.unsupported("No SIM card is in use", listOf(simEvidence))

        // Device policy, set by Advanced Protection or an organisation, overrides every other setting.
        val policy = cellular.twoGDisallowed()
        val evidence = buildList {
            add(simEvidence)
            if (policy is Reading.Value) {
                add(Evidence("2G turned off by device policy", if (policy.value) "yes" else "no", policy.source))
            }
        }
        if ((policy as? Reading.Value)?.value == true) {
            return Outcome.pass("2G is turned off by device policy (Advanced Protection or your organisation)", evidence)
        }
        return if (context.sdkInt <= ANDROID_11) {
            fromNetworkModes(inUse, evidence)
        } else {
            fromPrivilegedRead(inUse, evidence)
        }
    }

    /** Android 11 and older: the per-SIM network mode setting decides, and every app may read it. */
    private fun fromNetworkModes(inUse: List<SimCard>?, base: List<Evidence>): Outcome {
        if (inUse == null) return Outcome.unknown("Could not tell which SIMs are in use", base)
        val props = properties.all()
        // Where a SIM has no stored mode, Android uses the first value of this property.
        val default = (props as? Reading.Value)?.value?.get(DEFAULT_NETWORK)
            ?.split(',')?.firstOrNull()?.trim()?.toIntOrNull()
        val evidence = base.toMutableList()
        val allows = inUse.map { sim ->
            val subId = sim.subId
            if (subId == null) {
                evidence += Evidence("${sim.label} network mode", null, props.source, "subscription unknown")
                return@map null
            }
            val key = "$PREFERRED_NETWORK_MODE$subId"
            val stored = settings.global(key)
            val raw = (stored as? Reading.Value)?.value?.trim()
            val value = raw?.toIntOrNull() ?: if (stored is Reading.Value && raw == null) default else null
            val mode = value?.let { NetworkModes.of(it) }
            val note = when {
                stored !is Reading.Value -> (stored as? Reading.Unavailable)?.reason ?: "not readable"
                raw == null && default != null -> "not set, so the phone's default ($DEFAULT_NETWORK=$default) applies"
                raw == null -> "not set, and the phone's default is not readable"
                mode == null -> "unknown mode $raw"
                else -> "$key=$raw"
            }
            evidence += Evidence("${sim.label} network mode", mode?.label, stored.source, note)
            mode?.allows2g
        }
        val with2g = inUse.filterIndexed { i, _ -> allows[i] == true }
        return when {
            with2g.isNotEmpty() -> Outcome.fail(
                "The network mode of ${with2g.joinToString { it.label }} includes 2G, so the phone may connect to 2G networks",
                evidence,
            )
            allows.all { it == false } -> Outcome.pass("No SIM's network mode includes 2G", evidence)
            else -> Outcome.unknown("The network mode could not be read for every SIM", evidence)
        }
    }

    /** Android 12 and later: the shell user or root reads the network types each reason allows. */
    private fun fromPrivilegedRead(inUse: List<SimCard>?, base: List<Evidence>): Outcome {
        val read = cellular.privileged()
        if (read !is Reading.Value) {
            return Outcome.unknown(
                "Android 12 and later hide the Allow 2G switch and the network mode from apps; Droynis reads them " +
                    "with Shizuku or root",
                base + read.toEvidence("Allow 2G and network mode"),
            )
        }
        val wanted = inUse?.mapNotNull { it.subId }?.toSet()
        val sims = read.value.filter { wanted.isNullOrEmpty() || it.subId in wanted }
        if (sims.isEmpty()) return Outcome.unknown("The privileged read found no active SIM", base)

        val evidence = base.toMutableList()
        val allows = sims.map { sim ->
            if (sim.allowedNetworkTypes.isEmpty()) {
                evidence += Evidence("${sim.label} network types", null, read.source, "not readable")
                return@map null
            }
            sim.allowedNetworkTypes.toSortedMap().forEach { (reason, types) ->
                val name = NetworkTypes.REASONS[reason] ?: "Reason $reason"
                evidence += Evidence("${sim.label} · $name", describe(reason, types), read.source)
            }
            sim.allowedNetworkTypes.values.fold(ALL) { acc, types -> acc and types } and NetworkTypes.TWO_G != 0L
        }
        val with2g = sims.filterIndexed { i, _ -> allows[i] == true }
        return when {
            with2g.isNotEmpty() -> Outcome.fail(
                "${with2g.joinToString { it.label }} may connect to 2G networks" +
                    if (with2g.all { it.allows2gBySwitch() }) ": Allow 2G is on" else "",
                evidence,
            )
            allows.all { it == false } -> Outcome.pass("2G is off for every SIM in use", evidence)
            else -> Outcome.unknown("The allowed network types could not be read for every SIM", evidence)
        }
    }

    private fun SimTelephony.allows2gBySwitch(): Boolean =
        allowedNetworkTypes[NetworkTypes.REASON_ENABLE_2G]?.let { it and NetworkTypes.TWO_G != 0L } == true

    private fun describe(reason: Int, types: Long): String {
        val with2g = types and NetworkTypes.TWO_G != 0L
        return when (reason) {
            NetworkTypes.REASON_ENABLE_2G -> if (with2g) "on" else "off"
            0 -> if (with2g) "includes 2G" else "leaves out 2G"
            else -> if (with2g) "allows 2G" else "blocks 2G"
        }
    }

    companion object {
        const val PREFERRED_NETWORK_MODE = "preferred_network_mode"
        const val DEFAULT_NETWORK = "ro.telephony.default_network"
        private const val ANDROID_11 = 30
        private const val ALL = -1L
    }
}
