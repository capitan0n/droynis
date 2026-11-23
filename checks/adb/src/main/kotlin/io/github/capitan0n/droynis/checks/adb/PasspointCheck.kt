package io.github.capitan0n.droynis.checks.adb

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
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

class PasspointCheck(private val dumpsys: Dumpsys, private val supported: () -> Boolean) : Check {
    override val spec = CheckSpec(
        id = "NETW-3107",
        category = Category.NETWORK,
        title = "Hotspot 2.0 (Passpoint)",
        severity = Severity.INFO,
        explanation = "Passpoint lets your phone join participating Wi-Fi networks using a saved provider " +
            "profile. This shows the switch and, when readable for this user, each provider's auto-join setting.",
        remediation = Remediation("Review Passpoint subscriptions in Wi-Fi settings and remove providers you no longer use.",
            settingsActions = listOf(SettingsActions.WIFI_SAVED_NETWORKS, SettingsActions.WIFI)),
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "never (reports the Passpoint switch and readable provider settings)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        if (!supported()) return Outcome.unsupported("This device does not advertise Hotspot 2.0 support")
        val dump = dumpsys.dump(WifiMacCheck.SERVICE)
        return dump.evaluate("Hotspot 2.0", if (dump is Reading.Value) emptyList() else listOf(dump.toEvidence("Wi-Fi service"))) {
            val lines = dumpLines(it)
            val enabled = PasspointDump.enabled(lines)
            val providers = PasspointDump.providers(lines, context.appUid?.div(100_000))
            val evidence = buildList {
                add(Evidence("Hotspot 2.0", enabled?.let { on -> if (on) "on" else "off" }, dump.source))
                add(Evidence("Saved provider profiles", providers?.size?.toString(), dump.source,
                    note = if (providers == null) "not readable for this profile" else null))
                providers?.forEach { (domain, autoJoin) ->
                    add(Evidence("Provider", domain, dump.source, personal = true, note = when (autoJoin) {
                        true -> "auto-join allowed"
                        false -> "auto-join off"
                        null -> "auto-join setting unreadable"
                    }))
                }
            }
            when (enabled) {
                null -> Outcome.unknown("The Hotspot 2.0 switch could not be read", evidence)
                true -> Outcome.pass("Hotspot 2.0 is on", evidence)
                false -> Outcome.pass("Hotspot 2.0 is off", evidence)
            }
        }
    }
}

internal object PasspointDump {
    private const val begin = "PasspointManager - Providers Begin ---"
    private const val end = "PasspointManager - Providers End ---"
    private val domain = Regex("""(?=.{1,253}$)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+""")
    private val autoJoin = Regex("""CarrierId:-?[0-9]+SubscriptionId:-?[0-9]+IsAutojoinEnabled:(true|false)mIsMacRandomizationEnabled:""")

    fun enabled(lines: List<String>): Boolean? {
        // The manager's runtime flag and the saved switch should agree when both are present.
        val values = mutableListOf<Boolean>()
        for (i in lines.indices) {
            if (lines[i] == "Dump of PasspointManager" && lines.getOrNull(i + 1)?.startsWith("mEnabled: ") == true) {
                values += lines[i + 1].substringAfter(": ").toBooleanStrictOrNull() ?: return null
            }
            if (lines[i].startsWith("WifiPasspointState ") && lines.getOrNull(i - 1)?.startsWith("WifiScoringState ") == true) {
                values += lines[i].substringAfter(' ').toBooleanStrictOrNull() ?: return null
            }
        }
        return values.distinct().singleOrNull()
    }

    fun providers(lines: List<String>, user: Int?): List<Pair<String, Boolean?>>? {
        if (user == null || lines.filter { it.startsWith("WifiStateUser ") }.singleOrNull() != "WifiStateUser $user") return null
        val start = lines.indices.singleOrNull { lines[it] == begin } ?: return null
        val stop = lines.indices.singleOrNull { lines[it] == end } ?: return null
        if (stop <= start) return null
        val entries = lines.subList(start + 1, stop).filter { it.isNotBlank() }
        val starts = entries.indices.filter { entries[it].startsWith("ProviderId:") }
        if (entries.isNotEmpty() && starts.firstOrNull() != 0) return null
        return starts.mapIndexed { index, offset ->
            val block = entries.subList(offset, starts.getOrNull(index + 1) ?: entries.size)
            val configStart = block.indexOf("Configuration Begin ---")
            // PasspointProvider appends "Configuration End ---" directly to the last config field.
            val configEnd = block.indexOfFirst { it.endsWith("Configuration End ---") }
            val fqdn: String
            val allowed: Boolean?
            if (configStart >= 0) {
                if (configEnd <= configStart) return null
                val config = block.subList(configStart + 1, configEnd + 1)
                val home = config.indexOf("HomeSP Begin ---")
                if (home < 0) return null
                fqdn = config.getOrNull(home + 1)?.takeIf { it.startsWith("FQDN: ") }?.substringAfter(": ") ?: return null
                allowed = autoJoin.findAll(config.last()).singleOrNull()?.groupValues?.get(1)?.toBooleanStrictOrNull()
            } else {
                fqdn = block.singleOrNull { it.startsWith("FQDN:") }?.substringAfter(':')?.trim() ?: return null
                allowed = null
            }
            if (!domain.matches(fqdn)) return null
            fqdn to allowed
        }
    }
}
