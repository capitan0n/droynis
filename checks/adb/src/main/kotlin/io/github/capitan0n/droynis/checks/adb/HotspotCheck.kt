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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Reads the saved hotspot settings from `dumpsys wifi`. From Android 14, `WifiServiceImpl.dump`
 * prints `WifiApConfigStore config: ` and then `SoftApConfiguration.toString()`, one field per
 * line, followed by an empty line (checked in Android 14, 15, 16 and 17; Android 13 and older
 * don't print it):
 *
 * ```
 * WifiApConfigStore config: ssid = "Pixel 9"
 *  Passphrase = <non-empty>
 *  HiddenSsid = false
 *  Channels = {1=0}
 *  SecurityType = 2
 *  MaxClient = 0
 *  AutoShutdownEnabled = true
 *  ShutdownTimeoutMillis = -1
 *  …
 * ```
 *
 * The dump never prints the password, only whether one is set. The hotspot's name is the only free
 * text, on the first line and at most 32 bytes: a name with a line break can add one field line,
 * which then appears twice, or end the block early, which leaves a field missing. Either makes the
 * parse fail. Only the four fields below are kept: no name, address or channel.
 */
object HotspotDump {

    data class Hotspot(
        /** `SoftApConfiguration.SECURITY_TYPE_*`. */
        val securityType: Int,
        val hasPassword: Boolean,
        /** "Turn off hotspot automatically". */
        val autoShutdown: Boolean,
        /** How long it waits with no device connected; [DEFAULT_TIMEOUT] or 0 is Android's default. */
        val shutdownTimeoutMillis: Long,
    )

    sealed interface Result {
        data class Parsed(val hotspot: Hotspot) : Result

        data class Failed(val reason: String) : Result
    }

    /** `SoftApConfiguration.SECURITY_TYPE_*`. */
    const val OPEN = 0
    const val WPA2_PSK = 1
    const val WPA3_SAE_TRANSITION = 2
    const val WPA3_SAE = 3
    const val OWE_TRANSITION = 4
    const val OWE = 5

    /** Anyone in range can join: no password, encrypted (Enhanced Open) or not. */
    val NO_PASSWORD = setOf(OPEN, OWE_TRANSITION, OWE)

    /** `SoftApConfiguration.DEFAULT_TIMEOUT`: Android's own delay; legacy callers see it as 0. */
    const val DEFAULT_TIMEOUT = -1L

    internal const val PREFIX = "WifiApConfigStore config: "
    private const val PASSWORD = "Passphrase"
    private const val SECURITY = "SecurityType"
    private const val AUTO_SHUTDOWN = "AutoShutdownEnabled"
    private const val TIMEOUT = "ShutdownTimeoutMillis"
    private val FIELD = Regex("""^\s*($PASSWORD|$SECURITY|$AUTO_SHUTDOWN|$TIMEOUT) = (.*)$""")

    /** How Settings names each security type; null for a type Droynis doesn't know. */
    fun securityName(type: Int): String? = when (type) {
        OPEN -> "None"
        WPA2_PSK -> "WPA2-Personal"
        WPA3_SAE_TRANSITION -> "WPA2/WPA3-Personal"
        WPA3_SAE -> "WPA3-Personal"
        OWE_TRANSITION -> "Enhanced Open with an open fallback"
        OWE -> "Enhanced Open"
        else -> null
    }

    fun parse(text: String): Result {
        val lines = text.lines().map { it.trimEnd() }
        lines.firstOrNull { it.startsWith(WifiDump.NOT_STARTED) }?.let { return Result.Failed(it.trim()) }
        val starts = lines.indices.filter { lines[it].startsWith(PREFIX) }
        if (starts.isEmpty()) return Result.Failed("no hotspot settings in the output")
        if (starts.size > 1) return Result.Failed("the hotspot settings appear twice")
        val start = starts.single()
        val end = (start + 1 until lines.size).firstOrNull { lines[it].isBlank() } ?: lines.size

        val fields = mutableMapOf<String, String>()
        for (line in lines.subList(start + 1, end)) {
            val (name, value) = FIELD.matchEntire(line)?.destructured ?: continue
            if (fields.put(name, value.trim()) != null) return Result.Failed("the hotspot's $name appears twice")
        }
        fun missing(name: String) = Result.Failed("the hotspot settings have no $name")
        val password = when (fields[PASSWORD] ?: return missing(PASSWORD)) {
            "<non-empty>" -> true
            "<empty>" -> false
            else -> return Result.Failed("the hotspot's $PASSWORD is in an unknown shape")
        }
        val security = (fields[SECURITY] ?: return missing(SECURITY)).toIntOrNull()
            ?: return Result.Failed("the hotspot's $SECURITY is not a number")
        val autoShutdown = (fields[AUTO_SHUTDOWN] ?: return missing(AUTO_SHUTDOWN)).toBooleanStrictOrNull()
            ?: return Result.Failed("the hotspot's $AUTO_SHUTDOWN is neither true nor false")
        val timeout = (fields[TIMEOUT] ?: return missing(TIMEOUT)).toLongOrNull()
            ?: return Result.Failed("the hotspot's $TIMEOUT is not a number")
        return Result.Parsed(Hotspot(security, password, autoShutdown, timeout))
    }
}

class HotspotCheck(private val dumpsys: Dumpsys) : Check {

    override val spec = CheckSpec(
        id = "NETW-3103",
        category = Category.NETWORK,
        title = "Hotspot security",
        severity = Severity.NOTICE,
        explanation = "While the hotspot is on, every device that joins it uses your mobile data and shares a " +
            "network with your phone. Without a password (security None, or Enhanced Open, which only encrypts " +
            "the radio link) anyone in range can join. A hotspot that turns itself off once no device is " +
            "connected isn't left on by accident. Android keeps these settings in its Wi-Fi service, which only " +
            "the ADB, Shizuku or root tier can read.",
        remediation = Remediation(
            text = "Open Settings › Network & internet › Hotspot & tethering › Wi-Fi hotspot. Set Security to " +
                "WPA3-Personal, or WPA2/WPA3-Personal if older devices must join, with a long password, and turn " +
                "on \"Turn off hotspot automatically\".",
            settingsActions = listOf(SettingsActions.WIFI_HOTSPOT, SettingsActions.TETHERING, SettingsActions.NETWORK),
        ),
        // The saved hotspot settings appear in dumpsys from Android 14.
        minSdk = 34,
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "the hotspot has no password (a warning), or doesn't turn off by itself when no device is connected",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = dumpsys.dump(WifiMacCheck.SERVICE)
        if (dump !is Reading.Value) {
            return Outcome.unknown("The Wi-Fi service could not be read", listOf(dump.toEvidence("Wi-Fi service")))
        }
        val hotspot = when (val result = HotspotDump.parse(dump.value)) {
            is HotspotDump.Result.Failed -> return Outcome.unknown(
                "The Wi-Fi service's output is in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("Wi-Fi service", null, dump.source, note = result.reason)),
            )
            is HotspotDump.Result.Parsed -> result.hotspot
        }
        val security = HotspotDump.securityName(hotspot.securityType)
        val evidence = listOf(
            Evidence("Hotspot security", security ?: "type ${hotspot.securityType}", dump.source),
            Evidence("Hotspot password", if (hotspot.hasPassword) "set" else "none", dump.source),
            Evidence(
                "Turn off hotspot automatically",
                if (hotspot.autoShutdown) "on" else "off",
                dump.source,
                note = if (hotspot.autoShutdown) delay(hotspot.shutdownTimeoutMillis) else null,
            ),
        )
        if (security == null) {
            return Outcome.unknown("The hotspot uses a security type Droynis doesn't know (${hotspot.securityType})", evidence)
        }
        val open = hotspot.securityType in HotspotDump.NO_PASSWORD
        // Android refuses a password type without a password, and the other way around.
        if (open == hotspot.hasPassword) {
            return Outcome.unknown("The hotspot's settings don't add up: $security, password ${if (hotspot.hasPassword) "set" else "none"}", evidence)
        }
        // "None" says nothing more than "no password"; Enhanced Open is worth naming.
        val kind = if (hotspot.securityType == HotspotDump.OPEN) "" else " ($security)"
        return when {
            open && !hotspot.autoShutdown -> Outcome.fail(
                "The hotspot has no password$kind and doesn't turn off by itself",
                evidence,
                escalation = Severity.WARNING,
            )
            open -> Outcome.fail("The hotspot has no password$kind: anyone in range can join it", evidence, escalation = Severity.WARNING)
            !hotspot.autoShutdown -> Outcome.fail("The hotspot uses $security, but doesn't turn off by itself when no device is connected", evidence)
            else -> Outcome.pass("The hotspot uses $security and turns off by itself when no device is connected", evidence)
        }
    }

    private fun delay(millis: Long): String = when {
        millis <= 0 -> "after Android's default time with no device connected"
        millis < 60_000 -> "after ${count((millis / 1000).toInt().coerceAtLeast(1), "second")} with no device connected"
        else -> "after ${count((millis / 60_000).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), "minute")} with no device connected"
    }
}
