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

/**
 * Whether Magisk grants root to the ADB shell, not just to apps. Magisk's Superuser access setting
 * defaults to "Apps and ADB", so out of the box any computer trusted for USB debugging gets a root
 * shell with `adb shell su`. Only Magisk stores this in a form Droynis can read; KernelSU and APatch
 * keep it elsewhere.
 */
class AdbRootCheck(private val shell: RootShellProbe) : Check {

    override val spec = CheckSpec(
        id = "APPS-4302",
        category = Category.APPS,
        title = "Root access over ADB",
        severity = Severity.WARNING,
        explanation = "Magisk can hand root to apps, to the ADB shell, to both or to neither. The default is " +
            "both, so any computer you have trusted for USB debugging can run `adb shell su` and get a full root " +
            "shell, and so can malware on that computer. Limiting root to apps keeps adb, and anything reaching " +
            "the phone over it, out of root.",
        remediation = Remediation(
            text = "In the Magisk app, open Settings › Superuser access and set it to \"Apps only\". Keep USB " +
                "debugging off when you don't need it, and review the computers trusted for it (ACCS-2301).",
        ),
        requires = setOf(Grant.ROOT),
        failsWhen = "Magisk grants root to the ADB shell (Superuser access includes ADB; the default)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val manager = shell.manager()
        if (manager is Reading.Value && manager.value != RootManager.MAGISK) {
            return Outcome.unsupported(
                "Only Magisk exposes this; ${manager.value.label} keeps it in a form Droynis can't read",
                listOf(manager.toEvidenceManager()),
            )
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
                Outcome.fail("A computer with adb can get root: Magisk's Superuser access is \"$description\"", evidence)
            } else {
                Outcome.pass("The ADB shell can't get root: Magisk's Superuser access is \"$description\"", evidence)
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
        val rows = lines.mapNotNull { ROW.find(it) }
        if (rows.isEmpty()) return null
        return rows.associate { it.groupValues[1] to it.groupValues[2].toInt() }
    }
}
