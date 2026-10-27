package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.CellularProbe
import io.github.capitan0n.droynis.checks.base.CellularSecurity
import io.github.capitan0n.droynis.checks.base.PrivilegedSwitch
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
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Whether the phone refuses mobile connections without encryption ("null ciphers"), Android's
 * "Require encryption" switch. Only the system, the shell user and root may read it
 * (`TelephonyManager.isNullCipherAndIntegrityPreferenceEnabled`, Android 14+), and only phones whose
 * modem supports it have it.
 */
class CellularEncryptionCheck(private val cellular: CellularProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3202",
        category = Category.NETWORK,
        title = "Mobile network encryption",
        severity = Severity.NOTICE,
        explanation = "Calls, texts and mobile data are encrypted between the phone and the cell tower, but the " +
            "network can tell the phone to turn that off (a \"null cipher\"). Fake cell towers (IMSI catchers) do " +
            "exactly this to read texts, login codes included, and listen to calls. From Android 14, phones whose " +
            "modem supports it can refuse such connections; Settings calls it \"Require encryption\". A few " +
            "operators still use unencrypted connections, so with it on the phone may lose service in places; " +
            "emergency calls never need encryption.",
        remediation = Remediation(
            text = "Turn on Require encryption: Settings › Security & privacy › More security & privacy › Mobile " +
                "network security on Android 15 and later, or Settings › Network & internet › SIMs › your SIM on " +
                "Android 14 (the place varies by vendor). If calls or data stop working where you live, turn it off " +
                "again. Turning off Allow 2G (NETW-3010) blocks the most common way to force a weak connection too.",
            settingsActions = listOf(SettingsActions.CELLULAR_NETWORK_SECURITY, SettingsActions.MOBILE_NETWORK),
        ),
        minSdk = 34,
        requires = setOf(Grant.SHIZUKU),
        timeout = 20.seconds,
        failsWhen = "the phone accepts mobile connections without encryption (Require encryption is off)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val read = securityOrOutcome(cellular) { return it }
        val allowed = read.value.nullCipherAllowed
        val evidence = listOf(
            // Settings shows the opposite of the stored preference: "Require encryption" is on while null ciphers are not allowed.
            allowed.evidence("Require encryption", NULL_CIPHER_GETTER, read.source.grant, inverted = true),
        )
        return when {
            allowed.on == false -> Outcome.pass("The phone refuses mobile connections without encryption", evidence)
            allowed.on == true ->
                Outcome.fail("The phone accepts mobile connections without encryption: Require encryption is off", evidence)
            allowed.unsupported -> Outcome.unsupported("This phone's modem can't refuse unencrypted connections", evidence)
            else -> Outcome.unknown("Whether the phone requires encryption could not be read", evidence)
        }
    }

    private companion object {
        const val NULL_CIPHER_GETTER = "isNullCipherAndIntegrityPreferenceEnabled"
    }
}

/**
 * Whether the phone warns about signs of a fake cell tower: the network turning encryption off, and
 * asking for the SIM's or phone's identity in the clear (Android 15+, "Network notifications").
 * Only the system, the shell user and root may read them, and only phones whose modem supports them
 * have them.
 */
class CellularAlertsCheck(private val cellular: CellularProbe) : Check {

    override val spec = CheckSpec(
        id = "NETW-3203",
        category = Category.NETWORK,
        title = "Mobile network security alerts",
        severity = Severity.NOTICE,
        explanation = "From Android 15, phones whose modem supports it can warn you when the network asks for your " +
            "SIM's or phone's identity in the clear, or turns encryption off: both are signs of a fake cell tower " +
            "(IMSI catcher) nearby. Settings calls these \"Network notifications\". A warning doesn't stop the " +
            "attack, but tells you to keep sensitive calls and texts for later, or to switch to airplane mode.",
        remediation = Remediation(
            text = "Turn on Network notifications: Settings › Security & privacy › More security & privacy › Mobile " +
                "network security (the place varies by vendor).",
            settingsActions = listOf(SettingsActions.CELLULAR_NETWORK_SECURITY, SettingsActions.SECURITY),
        ),
        minSdk = 35,
        requires = setOf(Grant.SHIZUKU),
        timeout = 20.seconds,
        failsWhen = "the phone doesn't warn about signs of a fake cell tower (Network notifications are off)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val read = securityOrOutcome(cellular) { return it }
        val grant = read.source.grant
        val alerts = listOf(
            Alert("connections without encryption", "Alerts for connections without encryption", "isNullCipherNotificationsEnabled", read.value.nullCipherAlerts),
            Alert("identity requests in the clear", "Alerts for identity requests", "isCellularIdentifierDisclosureNotificationsEnabled", read.value.identifierAlerts),
        )
        val evidence = alerts.map { it.switch.evidence(it.label, it.getter, grant) }
        val supported = alerts.filterNot { it.switch.unsupported }
        if (supported.isEmpty()) return Outcome.unsupported("This phone's modem can't warn about fake cell towers", evidence)

        val off = supported.filter { it.switch.on == false }
        return when {
            off.isNotEmpty() ->
                Outcome.fail("The phone doesn't warn about ${off.map { it.phrase }.joinNames()}, signs of a fake cell tower", evidence)
            supported.all { it.switch.on == true } -> Outcome.pass("The phone warns about signs of a fake cell tower", evidence)
            else -> Outcome.unknown("Whether the phone warns about fake cell towers could not be read", evidence)
        }
    }

    private class Alert(val phrase: String, val label: String, val getter: String, val switch: PrivilegedSwitch)
}

/**
 * The privileged read of the security switches, or the outcome a check returns without it: N/A on a
 * device with no mobile network, Unknown when Shizuku or root couldn't read it.
 */
private inline fun securityOrOutcome(cellular: CellularProbe, exit: (Outcome) -> Nothing): Reading.Value<CellularSecurity> {
    val sims = cellular.sims()
    if (sims is Reading.Unsupported) exit(Outcome.unsupported("This device has no mobile network", listOf(sims.toEvidence("Mobile network"))))
    return when (val read = cellular.security()) {
        is Reading.Value -> read
        is Reading.Unsupported -> exit(Outcome.unsupported("This device has no mobile network security switches", listOf(read.toEvidence(LABEL))))
        is Reading.Unavailable -> exit(
            Outcome.unknown("The mobile network security switches could not be read (${read.reason})", listOf(read.toEvidence(LABEL))),
        )
    }
}

private const val LABEL = "Mobile network security"

/** One switch as evidence, with the `ITelephony` getter that read it; [inverted] shows Settings' sense of it. */
private fun PrivilegedSwitch.evidence(label: String, getter: String, grant: Grant?, inverted: Boolean = false) = Evidence(
    label,
    on?.let { if (it != inverted) "on" else "off" },
    Source("ITelephony.$getter()", grant),
    note = when {
        unsupported -> "not supported by this phone's modem ($error)"
        on == null -> "not readable${error?.let { ": $it" }.orEmpty()}"
        else -> null
    },
)
