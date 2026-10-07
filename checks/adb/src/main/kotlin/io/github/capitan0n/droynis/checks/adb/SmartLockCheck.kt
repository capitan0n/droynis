package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.PackageInventory
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
 * Reads `dumpsys trust`, checked against TrustManagerService in Android 17:
 *
 * ```
 * Trust manager state:
 *  User "Owner" (id=0, flags=0x13) (current): trustState=TRUSTED, trustManaged=1, deviceLocked=0, …
 *    Enabled agents:
 *     com.google.android.gms/.auth.trustagent.GoogleTrustAgent
 *      bound=1, connected=1, managingTrust=1, trusted=1
 *       message="…"
 *    Events:
 * ```
 *
 * Only the current user's `trustManaged` flag and its agents are read. The user's name is never
 * kept, and neither is an agent's message, which can name a place or a device.
 */
object TrustDump {

    data class Agent(val component: String, val managingTrust: Boolean, val trusted: Boolean)

    sealed interface Result {
        /** [activeUnlock] is null where Android doesn't report it (before Android 14). */
        data class Parsed(val trustManaged: Boolean, val activeUnlock: Boolean?, val agents: List<Agent>) : Result

        data class Failed(val reason: String) : Result
    }

    private val USER = Regex("""^\s*User ".*" \(id=\d+, flags=0x[0-9a-fA-F]+\)""")
    private val MANAGED = Regex("""trustManaged=([01])""")
    private val ACTIVE_UNLOCK = Regex("""isActiveUnlockRunning=([01])""")
    private val COMPONENT = Regex("""^\s+([\w.]+/[\w.$]+)$""")
    private val FLAGS = Regex("""^\s+bound=[01], connected=[01], managingTrust=([01]), trusted=([01])$""")

    fun parse(text: String): Result {
        val lines = text.lines().map { it.trimEnd() }
        lines.firstOrNull { it.trim().startsWith("disabled because") }?.let { return Result.Failed(it.trim()) }
        val start = lines.indexOfFirst { USER.containsMatchIn(it) && "(current)" in it }
        if (start < 0) return Result.Failed("no current user in the output")
        val managed = MANAGED.find(lines[start])?.groupValues?.get(1)
            ?: return Result.Failed("no trustManaged flag for the current user")
        val activeUnlock = ACTIVE_UNLOCK.find(lines[start])?.groupValues?.get(1)

        val agents = mutableListOf<Agent>()
        var component: String? = null
        for (line in lines.drop(start + 1)) {
            // The current user's part ends at its events, or at the next user.
            if (line.trim() == "Events:" || USER.containsMatchIn(line)) break
            COMPONENT.matchEntire(line)?.let {
                component = it.groupValues[1]
                return@let
            }
            FLAGS.matchEntire(line)?.let {
                val name = component ?: return Result.Failed("agent flags without an agent")
                agents += Agent(name, it.groupValues[1] == "1", it.groupValues[2] == "1")
                component = null
            }
        }
        return Result.Parsed(managed == "1", activeUnlock?.let { it == "1" }, agents)
    }
}

class SmartLockCheck(
    private val dumpsys: Dumpsys,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2101",
        category = Category.ACCESS_CONTROL,
        title = "Smart Lock and Extend Unlock",
        severity = Severity.NOTICE,
        explanation = "Smart Lock (Extend Unlock on newer phones) keeps the phone unlocked near a trusted " +
            "device or place, or while you carry it. Whoever takes it from your pocket, or picks it up " +
            "next to your car's Bluetooth, gets an unlocked phone. Android keeps this in its trust " +
            "service, which only the ADB, Shizuku or root tier can read.",
        remediation = Remediation(
            text = "Open Settings › Security › Smart Lock or Extend Unlock (the location varies by vendor) " +
                "and remove trusted devices, trusted places and on-body detection you don't need.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        requires = setOf(Grant.DUMP),
        timeout = 10.seconds,
        failsWhen = "a trust agent such as Smart Lock can keep the phone unlocked",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = dumpsys.dump(SERVICE)
        if (dump !is Reading.Value) {
            return Outcome.unknown("The trust service could not be read", listOf(dump.toEvidence("Trust agents")))
        }
        val parsed = when (val result = TrustDump.parse(dump.value)) {
            is TrustDump.Result.Failed -> return Outcome.unknown(
                "The trust service's output is in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("Trust agents", null, dump.source, note = result.reason)),
            )
            is TrustDump.Result.Parsed -> result
        }
        val evidence = buildList {
            add(Evidence("Trust managed", if (parsed.trustManaged) "yes" else "no", dump.source))
            parsed.activeUnlock?.let { add(Evidence("Active unlock running", if (it) "yes" else "no", dump.source)) }
            parsed.agents.forEach { agent ->
                val pkg = agent.component.substringBefore('/')
                add(
                    Evidence(
                        "Trust agent",
                        "${packages.label(pkg)} (${agent.component})",
                        dump.source,
                        note = when {
                            agent.trusted -> "keeping the phone unlocked now"
                            agent.managingTrust -> "set up, may keep the phone unlocked"
                            else -> "enabled, not set up"
                        },
                    ),
                )
            }
        }
        val managing = parsed.agents.filter { it.managingTrust }.map { packages.label(it.component.substringBefore('/')) }.distinct()
        if (!parsed.trustManaged && parsed.activeUnlock != true) {
            return Outcome.pass("No trust agent can keep the phone unlocked", evidence)
        }
        val who = if (managing.isEmpty()) "A trust agent" else managing.joinNames()
        return Outcome.fail("$who can keep the phone unlocked", evidence)
    }

    companion object {
        const val SERVICE = "trust"
    }
}
