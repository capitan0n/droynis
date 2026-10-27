package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading

/** A SIM in use. Android tells apps its slot and subscription without any permission. */
data class SimCard(
    /** 0 for the first SIM slot; null below Android 10, which doesn't tell apps. */
    val slot: Int?,
    /** The subscription's local number in Android's SIM list (1, 2, …); null when unknown. */
    val subId: Int?,
) {
    /** "SIM 1" for the first slot, as Settings names it. */
    val label: String get() = slot?.let { "SIM ${it + 1}" } ?: subId?.let { "SIM (subscription $it)" } ?: "SIM"
}

/** What only privileged callers may read about one active SIM: the shell user (Shizuku) or root. */
data class SimTelephony(
    val subId: Int,
    /** Null when Android reports no slot for it. */
    val slot: Int?,
    /** Whether the SIM asks for its PIN (Android 11+); null when this Android can't say. */
    val pinLocked: Boolean?,
    /**
     * The network types each reason allows, as `TelephonyManager.NETWORK_TYPE_BITMASK_*` bits by
     * `ALLOWED_NETWORK_TYPES_REASON_*` (Android 12+); empty when this Android can't say.
     */
    val allowedNetworkTypes: Map<Int, Long> = emptyMap(),
) {
    val label: String get() = SimCard(slot, subId).label
}

/**
 * One device-wide switch the privileged reader asked the telephony service about: its value, or the
 * exception that stopped the read.
 */
data class PrivilegedSwitch(val on: Boolean?, val error: String? = null) {
    /**
     * The modem, its HAL or this Android has no such switch: the service throws
     * UnsupportedOperationException, and a release without the method has no such call at all.
     */
    val unsupported: Boolean get() = on == null && error in UNSUPPORTED

    private companion object {
        val UNSUPPORTED = setOf("UnsupportedOperationException", "NoSuchMethodException")
    }
}

/** Mobile network security switches, device-wide, as only the shell user (Shizuku) or root may read them. */
data class CellularSecurity(
    /**
     * `isNullCipherAndIntegrityPreferenceEnabled` (Android 14+): true while the phone accepts
     * connections without encryption, that is while Settings' "Require encryption" is off.
     */
    val nullCipherAllowed: PrivilegedSwitch,
    /** `isNullCipherNotificationsEnabled` (Android 15+): a warning when the network turns encryption off. */
    val nullCipherAlerts: PrivilegedSwitch,
    /**
     * `isCellularIdentifierDisclosureNotificationsEnabled` (Android 15+): a warning when the network
     * asks for the SIM's or phone's identity in the clear, as fake cell towers do.
     */
    val identifierAlerts: PrivilegedSwitch,
)

interface CellularProbe {
    /** The SIMs in use right now; empty without a SIM. Unsupported on devices without mobile network. */
    fun sims(): Reading<List<SimCard>>

    /** `UserManager.DISALLOW_CELLULAR_2G`, which Advanced Protection and device policy set (Android 14+). */
    fun twoGDisallowed(): Reading<Boolean>

    /** Every active SIM as the shell user or root reads it; Unavailable without Shizuku or root. */
    fun privileged(): Reading<List<SimTelephony>>

    /** The device-wide mobile network security switches, from the same privileged read as [privileged]. */
    fun security(): Reading<CellularSecurity>
}

/**
 * The text Droynis' privileged telephony reader prints: a header line, then one line per active
 * SIM, e.g. `sub=1 slot=0 pin=true reason0=1048575 reason3=1015732`, and one line of device-wide
 * switches, e.g. `security null_cipher=true null_cipher_alerts=? null_cipher_alerts_error=UnsupportedOperationException`.
 * A value it could not read is left out or written as `?`, and a line `error=…` replaces the other
 * lines when nothing could be read.
 */
object TelephonyDump {
    const val HEADER = "droynis-telephony 1"

    /** Starts the line of device-wide switches. */
    const val SECURITY = "security"

    /** The keys of the device-wide switches on the [SECURITY] line. */
    const val NULL_CIPHER = "null_cipher"
    const val NULL_CIPHER_ALERTS = "null_cipher_alerts"
    const val IDENTIFIER_ALERTS = "id_alerts"

    sealed interface Result {
        /** [security] is null when the reader printed no [SECURITY] line. */
        data class Parsed(val sims: List<SimTelephony>, val security: CellularSecurity? = null) : Result

        data class Failed(val reason: String) : Result
    }

    fun parse(text: String): Result {
        val lines = text.lines().map { it.trim() }
        val start = lines.indexOf(HEADER)
        if (start < 0) {
            val said = lines.filter { it.isNotEmpty() }.joinToString(" ").take(MAX_QUOTE)
            return Result.Failed(if (said.isEmpty()) "the reader printed nothing" else "unexpected output: $said")
        }
        val body = lines.drop(start + 1).filter { it.isNotEmpty() }
        body.firstOrNull { it.startsWith("error=") }?.let { return Result.Failed(it.removePrefix("error=").take(MAX_QUOTE)) }
        val sims = body.filter { it.startsWith("sub=") }.map { line ->
            val fields = fieldsOf(line)
            val subId = fields["sub"]?.toIntOrNull()
                ?: return Result.Failed("a SIM line without a subscription: ${line.take(MAX_QUOTE)}")
            SimTelephony(
                subId = subId,
                slot = fields["slot"]?.toIntOrNull()?.takeIf { it >= 0 },
                pinLocked = when (fields["pin"]) {
                    "true" -> true
                    "false" -> false
                    else -> null
                },
                allowedNetworkTypes = fields.mapNotNull { (key, value) ->
                    val reason = key.removePrefix("reason").takeIf { key.startsWith("reason") }?.toIntOrNull()
                    val types = value.toLongOrNull()
                    if (reason == null || types == null) null else reason to types
                }.toMap(),
            )
        }
        val security = body.firstOrNull { it.startsWith("$SECURITY ") }?.let { line ->
            val fields = fieldsOf(line)
            fun switch(key: String) = PrivilegedSwitch(
                on = when (fields[key]) {
                    "true" -> true
                    "false" -> false
                    else -> null
                },
                error = fields["${key}_error"],
            )
            CellularSecurity(switch(NULL_CIPHER), switch(NULL_CIPHER_ALERTS), switch(IDENTIFIER_ALERTS))
        }
        return Result.Parsed(sims, security)
    }

    private fun fieldsOf(line: String): Map<String, String> = line.split(' ').mapNotNull { token ->
        val eq = token.indexOf('=')
        if (eq <= 0) null else token.substring(0, eq) to token.substring(eq + 1)
    }.toMap()

    private const val MAX_QUOTE = 160
}

/** `TelephonyManager.NETWORK_TYPE_BITMASK_*` bits Android counts as 2G (`NETWORK_CLASS_BITMASK_2G`). */
object NetworkTypes {
    const val GPRS = 1L
    const val EDGE = 2L
    const val CDMA = 8L
    const val ONE_X_RTT = 64L
    const val GSM = 32768L
    const val TWO_G = GSM or GPRS or EDGE or CDMA or ONE_X_RTT

    /** `TelephonyManager.ALLOWED_NETWORK_TYPES_REASON_*`, as Settings presents each. */
    val REASONS = mapOf(
        0 to "Network mode",
        1 to "Power saving",
        2 to "Carrier",
        3 to "Allow 2G switch",
        4 to "Device policy",
    )

    const val REASON_ENABLE_2G = 3
}

/**
 * `RILConstants.NETWORK_MODE_*`, which Android 11 and older store per SIM in the
 * `preferred_network_mode<subId>` setting, with the names Settings shows and whether each mode
 * includes 2G (GSM, or CDMA 1x, which Android counts as 2G too).
 */
object NetworkModes {
    data class Mode(val label: String, val allows2g: Boolean)

    private val MODES = mapOf(
        0 to Mode("3G/2G (3G preferred)", true),
        1 to Mode("2G only", true),
        2 to Mode("3G only", false),
        3 to Mode("3G/2G (auto)", true),
        4 to Mode("CDMA and EvDo", true),
        5 to Mode("CDMA only", true),
        6 to Mode("EvDo only", false),
        7 to Mode("Global (GSM/WCDMA, CDMA, EvDo)", true),
        8 to Mode("LTE, CDMA and EvDo", true),
        9 to Mode("LTE/3G/2G (auto)", true),
        10 to Mode("LTE, CDMA, EvDo, GSM and WCDMA", true),
        11 to Mode("LTE only", false),
        12 to Mode("LTE/3G", false),
        13 to Mode("TD-SCDMA only", false),
        14 to Mode("TD-SCDMA and WCDMA", false),
        15 to Mode("LTE and TD-SCDMA", false),
        16 to Mode("TD-SCDMA and GSM", true),
        17 to Mode("LTE, TD-SCDMA and GSM", true),
        18 to Mode("TD-SCDMA, GSM and WCDMA", true),
        19 to Mode("LTE, TD-SCDMA and WCDMA", false),
        20 to Mode("LTE, TD-SCDMA, GSM and WCDMA", true),
        21 to Mode("TD-SCDMA, CDMA, EvDo, GSM and WCDMA", true),
        22 to Mode("LTE, TD-SCDMA, CDMA, EvDo, GSM and WCDMA", true),
        23 to Mode("5G only", false),
        24 to Mode("5G/LTE", false),
        25 to Mode("5G, LTE, CDMA and EvDo", true),
        26 to Mode("5G/LTE/3G/2G (auto)", true),
        27 to Mode("5G, LTE, CDMA, EvDo, GSM and WCDMA", true),
        28 to Mode("5G/LTE/3G", false),
        29 to Mode("5G, LTE and TD-SCDMA", false),
        30 to Mode("5G, LTE, TD-SCDMA and GSM", true),
        31 to Mode("5G, LTE, TD-SCDMA and WCDMA", false),
        32 to Mode("5G, LTE, TD-SCDMA, GSM and WCDMA", true),
        33 to Mode("5G, LTE, TD-SCDMA, CDMA, EvDo, GSM and WCDMA", true),
    )

    /** The mode for a stored value; null for a value this table doesn't know (a vendor's own mode). */
    fun of(value: Int): Mode? = MODES[value]
}
