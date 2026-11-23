package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
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

fun interface TetheringProbe {
    suspend fun active(canDump: Boolean): Reading<Set<String>>
}

class ActiveTetheringCheck(private val probe: TetheringProbe) : Check {
    override val spec = CheckSpec(
        id = "NETW-3013",
        category = Category.NETWORK,
        title = "Active tethering",
        severity = Severity.INFO,
        explanation = "Shows how this phone is currently offering to share its internet connection. " +
            "Sharing can be active even when no client is connected. Android 16 and later can report " +
            "this directly. Earlier versions need the ADB tier and a readable tethering service.",
        remediation = Remediation("Open Hotspot & tethering to stop sharing when you are finished.",
            settingsActions = listOf(SettingsActions.TETHERING, SettingsActions.NETWORK)),
        timeout = 20.seconds,
        failsWhen = "the phone is sharing a connection (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val result = probe.active(context.capabilities.has(Grant.DUMP))
        val evidence = listOf(result.toEvidence("Tethering") { it.sorted().joinToString().ifEmpty { "off" } })
        return result.evaluate("Active tethering", evidence) {
            if (it.isEmpty()) Outcome.pass("Tethering is off", evidence)
            else Outcome.fail("Tethering is active over ${it.sorted().joinToString()}", evidence)
        }
    }
}
