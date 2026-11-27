package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate

/** Magisk's ADB request switch on older releases and the saved shell grant on 31.1. */
class AdbRootCheck(private val shell: RootShellProbe) : Check {

    override val spec = CheckSpec(
        id = "APPS-4302",
        category = Category.APPS,
        title = "Root access over ADB",
        severity = Severity.WARNING,
        explanation = "A computer trusted for USB debugging can send commands as Android's shell user. " +
            "Older Magisk versions have a switch that lets the shell request root. Magisk 31.1 uses a saved " +
            "superuser grant for the shell instead.",
        remediation = Remediation(
            text = "In Magisk 31.1, review Shell in the Superuser tab. On earlier releases, choose Apps only " +
                "under Settings › Superuser access. Review your trusted computers in ACCS-2301.",
        ),
        requires = setOf(Grant.ROOT),
        failsWhen = "Magisk allows ADB to request root, or the ADB shell has an unexpired Magisk 31.1 grant",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val manager = shell.manager()
        if (manager is Reading.Value && manager.value != RootManager.MAGISK) {
            return Outcome.unsupported(
                "Only Magisk exposes this; ${manager.value.label} keeps it in a form Droynis can't read",
                listOf(manager.toEvidenceManager()),
            )
        }
        val version = shell.magiskVersion()
        if (version !is Reading.Value || version.value > 31100) return Outcome.unknown("Could not identify Magisk's ADB access model")
        if (version.value == 31100) {
            val table = shell.magiskPolicies()
            val policies = (table as? Reading.Value)?.let { MagiskPolicies.parse(it.value) }
                ?: return Outcome.unknown("Could not read the ADB shell's Magisk grant")
            val shellGrant = policies.singleOrNull { it.uid == 2000 }
            if (policies.count { it.uid == 2000 } > 1 || (shellGrant != null && shellGrant.policy !in 0..3)) {
                return Outcome.unknown("Unrecognized ADB shell grant")
            }
            val allowed = shellGrant?.grantsRoot(context.startedAt.toEpochSecond()) == true
            val evidence = listOf(Evidence("ADB shell (UID 2000)", if (allowed) "root granted" else "no current grant", table.source))
            return if (allowed) Outcome.fail("The ADB shell has a saved Magisk root grant", evidence)
                else Outcome.pass("The ADB shell has no current Magisk root grant", evidence)
        }
        val reading = shell.magiskSettings()
        return reading.evaluate("Magisk's Superuser access", listOf(reading.toEvidenceRaw())) { raw ->
            val map = MagiskSettings.parse(raw)
                ?: return@evaluate Outcome.unknown(
                    "Magisk's settings were not in the expected format",
                    listOf(Evidence("Magisk settings", "unexpected format", reading.source)),
                )
            val fromDefault = ROOT_ACCESS !in map
            val rootAccess = map[ROOT_ACCESS] ?: DEFAULT_ROOT_ACCESS
            if (rootAccess !in DISABLED..APPS_AND_ADB) {
                return@evaluate Outcome.unknown("Unrecognized Magisk Superuser access setting",
                    listOf(Evidence("Superuser access", rootAccess.toString(), reading.source)))
            }
            val description = describe(rootAccess)
            val evidence = listOf(
                Evidence(
                    "Superuser access",
                    "$description (root_access=$rootAccess)",
                    reading.source,
                    note = if (fromDefault) "not set; Magisk's default is Apps and ADB" else null,
                ),
            )
            if (rootAccess == ADB_ONLY || rootAccess == APPS_AND_ADB) {
                Outcome.fail("The ADB shell can request root: Magisk's Superuser access is \"$description\"", evidence)
            } else {
                Outcome.pass("Magisk blocks root requests from the ADB shell: Superuser access is \"$description\"", evidence)
            }
        }
    }

    private fun Reading<RootManager>.toEvidenceManager(): Evidence =
        Evidence("Root manager", (this as? Reading.Value)?.value?.label, source)

    private fun Reading<String>.toEvidenceRaw(): Evidence =
        Evidence("Magisk settings", (this as? Reading.Value)?.let { "read" }, source)

    companion object {
        const val ROOT_ACCESS = "root_access"

        // Mirrors Magisk's MagiskDB ROOT_ACCESS constants.
        const val DISABLED = 0
        const val APPS_ONLY = 1
        const val ADB_ONLY = 2
        const val APPS_AND_ADB = 3

        /** Magisk's default when the row is absent. */
        const val DEFAULT_ROOT_ACCESS = APPS_AND_ADB

        private fun describe(value: Int): String = when (value) {
            DISABLED -> "disabled"
            APPS_ONLY -> "apps only"
            ADB_ONLY -> "ADB only"
            APPS_AND_ADB -> "apps and ADB"
            else -> "an unknown setting ($value)"
        }
    }
}

/** Magisk's `settings` table, one `key=…|value=…` per line. */
object MagiskSettings {
    private val ROW = Regex("""^key=([a-z0-9_]+)\|value=(-?\d+)$""")

    /** The settings in [text]; an empty map when nothing is stored, null when non-blank output parses to nothing. */
    fun parse(text: String): Map<String, Int>? {
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) return emptyMap()
        val settings = mutableMapOf<String, Int>()
        for (line in lines) {
            val match = ROW.matchEntire(line) ?: return null
            val (key, raw) = match.destructured
            if (settings.put(key, raw.toIntOrNull() ?: return null) != null) return null
        }
        return settings
    }
}
