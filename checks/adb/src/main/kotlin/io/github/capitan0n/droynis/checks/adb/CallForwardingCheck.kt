package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.CellularProbe
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
 * Reads the call forwarding indicator from `dumpsys telephony.registry`: `TelephonyRegistry` keeps,
 * for each phone (SIM slot), the state the status bar's forwarding icon shows, and prints it under
 * "last known state" as `mCallForwarding=true|false` after a `Phone Id=<slot>` line. The indicator is
 * unconditional forwarding ("Always forward"), as the network or the SIM reports it.
 *
 * Only these booleans are kept: the same dump prints the last caller's number and the cell the phone
 * is on, which never leave the parser.
 */
object TelephonyRegistryDump {

    sealed interface Result {
        /** Call forwarding by phone id (the SIM slot index). */
        data class Parsed(val callForwarding: Map<Int, Boolean>) : Result

        data class Failed(val reason: String) : Result
    }

    private val PHONE = Regex("""Phone Id=(\d+)""")
    private const val FORWARDING = "mCallForwarding="

    fun parse(text: String): Result {
        var phone: Int? = null
        var sawPhone = false
        val forwarding = linkedMapOf<Int, Boolean>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            PHONE.matchEntire(line)?.let {
                phone = it.groupValues[1].toIntOrNull() ?: return Result.Failed("a phone id that isn't a number: $line")
                sawPhone = true
            }
            if (!line.startsWith(FORWARDING)) continue
            val value = when (line.removePrefix(FORWARDING)) {
                "true" -> true
                "false" -> false
                else -> return Result.Failed("an unexpected value: ${line.take(MAX_QUOTE)}")
            }
            // Single-SIM releases print the state without a phone id: that is the first slot.
            val id = phone ?: if (sawPhone) return Result.Failed("a state outside a phone's section") else 0
            val earlier = forwarding.put(id, value)
            if (earlier != null && earlier != value) return Result.Failed("two different states for phone $id")
        }
        if (forwarding.isEmpty()) return Result.Failed("no call forwarding state in the output")
        return Result.Parsed(forwarding)
    }

    private const val MAX_QUOTE = 80
}

class CallForwardingCheck(
    private val dumpsys: Dumpsys,
    private val cellular: CellularProbe,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3106",
        category = Category.NETWORK,
        title = "Call forwarding",
        severity = Severity.WARNING,
        explanation = "While a SIM forwards all calls, your phone never rings: every call, including the ones " +
            "banks and apps make to read you a code, goes to another number. Someone holding your unlocked phone " +
            "for a moment can set it up by dialling a short code, and some account-takeover scams talk people " +
            "into dialling it. Android keeps the state of the forwarding icon for each SIM, and Droynis reads " +
            "that. Forwarding set up at your carrier without this phone may not show here, and forwarding only " +
            "when you're busy or don't answer, which voicemail uses, isn't counted.",
        remediation = Remediation(
            text = "Turn it off in the Phone app › Settings › Calling accounts (or Calls) › your SIM › Call " +
                "forwarding › Always forward, or dial #21# and press Call. Dial *#21# to ask your carrier what is " +
                "set. If you didn't set it up, ask your carrier who did, and review accounts that send you codes " +
                "by phone call.",
            settingsActions = listOf(SettingsActions.CALL_SETTINGS),
        ),
        requires = setOf(Grant.DUMP),
        timeout = 20.seconds,
        failsWhen = "a SIM in use forwards all calls to another number",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val sims = cellular.sims()
        when {
            sims is Reading.Unsupported ->
                return Outcome.unsupported("This device has no mobile network", listOf(sims.toEvidence("SIMs in use")))
            sims is Reading.Value && sims.value.isEmpty() ->
                return Outcome.unsupported("No SIM is in use", listOf(Evidence("SIMs in use", "none", sims.source)))
        }
        val dump = dumpsys.dump(SERVICE)
        if (dump !is Reading.Value) {
            return Outcome.unknown("The telephony registry could not be read", listOf(dump.toEvidence("Telephony registry")))
        }
        val state = when (val result = TelephonyRegistryDump.parse(dump.value)) {
            is TelephonyRegistryDump.Result.Failed -> return Outcome.unknown(
                "The telephony registry's output is in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("Telephony registry", null, dump.source, note = result.reason)),
            )
            is TelephonyRegistryDump.Result.Parsed -> result.callForwarding
        }
        // The registry's phone id is the SIM slot. When Android doesn't say which slot a SIM is in,
        // every slot it lists is judged; an empty slot reports no forwarding.
        val inUse = (sims as? Reading.Value)?.value
        val targets: List<Pair<String, Int>> = if (inUse != null && inUse.all { it.slot != null }) {
            inUse.map { it.label to it.slot!! }
        } else {
            state.keys.sorted().map { "SIM slot ${it + 1}" to it }
        }

        val evidence = targets.map { (label, slot) ->
            when (val on = state[slot]) {
                null -> Evidence("Call forwarding, $label", null, dump.source, note = "not in the telephony registry")
                else -> Evidence("Call forwarding, $label", if (on) "forwards all calls" else "doesn't forward all calls", dump.source)
            }
        }
        val forwarded = targets.filter { state[it.second] == true }.map { it.first }
        if (forwarded.isNotEmpty()) {
            val verb = if (forwarded.size == 1) "forwards" else "forward"
            return Outcome.fail("${forwarded.joinNames()} $verb all calls to another number", evidence)
        }
        val unread = targets.filter { state[it.second] == null }.map { it.first }
        if (unread.isNotEmpty()) {
            return Outcome.unknown("Call forwarding could not be read for ${unread.joinNames()}", evidence)
        }
        return Outcome.pass(
            if (targets.size == 1) "${targets.single().first} doesn't forward all calls" else "No SIM in use forwards all calls",
            evidence,
        )
    }

    companion object {
        const val SERVICE = "telephony.registry"
    }
}
