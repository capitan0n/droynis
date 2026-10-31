package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

/**
 * Boot scripts root runs from `/data/adb` (`service.d`, `post-fs-data.d`, and each module's
 * `post-fs-data.sh`/`service.sh`). A script root executes at boot is only as trustworthy as whoever
 * can write it: if the file, or any directory holding it, is owned by a non-root user or is writable
 * by group or others, that user can replace the script and have their code run as root next boot.
 * Normally `/data/adb` is `700 root`, so this passes.
 */
class BootScriptsCheck(private val shell: RootShellProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1302",
        category = Category.DEVICE_INTEGRITY,
        title = "Root boot code others can change",
        severity = Severity.NOTICE,
        explanation = "Your root manager runs the scripts in /data/adb/service.d and post-fs-data.d, and each " +
            "module's own boot scripts, as root every time the phone starts. If one of those files, or a folder " +
            "on the way to it, can be written by a user other than root, that user can swap in their own code " +
            "and it runs with full root rights at the next boot.",
        remediation = Remediation(
            text = "Make every boot script and its folders owned by root and writable by root alone: for a file, " +
                "`chown root:root <file>` and `chmod 700 <file>`; check that /data/adb and its subfolders are 700 " +
                "root too. A module's scripts are fixed by removing or reinstalling the module from a source you " +
                "trust.",
        ),
        requires = setOf(Grant.ROOT),
        failsWhen = "a boot script root runs, or a folder holding it, is not owned by root or is writable by others",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val reading = shell.bootScripts()
        return reading.evaluate("The root boot scripts", listOf(reading.toEvidence("Root boot scripts"))) { raw ->
            val entries = BootScripts.parse(raw)
                ?: return@evaluate Outcome.unknown(
                    "The boot-script listing was not in the expected format",
                    listOf(Evidence("Root boot scripts", "unexpected format", reading.source)),
                )
            val dirs = entries.filter { it.isDir }.associateBy { it.path }
            val scripts = entries.filter { !it.isDir }
            val exposed = scripts.filter { it.writableByOthers || dirs[it.parent]?.writableByOthers == true }
            val evidence = scripts.map { script ->
                val badDir = dirs[script.parent]?.takeIf { it.writableByOthers }
                Evidence(
                    "Boot script",
                    "${script.path} (${script.perms} ${script.owner})",
                    reading.source,
                    note = when {
                        script.writableByOthers -> "not owned by root, or writable by others"
                        badDir != null -> "its folder ${badDir.path} is ${badDir.perms} ${badDir.owner}"
                        else -> null
                    },
                )
            }
            when {
                exposed.isNotEmpty() -> Outcome.fail(
                    "${exposed.size.scriptsPhrase()} root runs at boot can be changed by something other than root: " +
                        exposed.map { it.name }.joinNames(),
                    evidence,
                )
                scripts.isEmpty() -> Outcome.pass("No root boot scripts are present in /data/adb", evidence)
                else -> Outcome.pass("Every root boot script is root-owned and not writable by others", evidence)
            }
        }
    }

    private fun Int.scriptsPhrase(): String = if (this == 1) "1 boot script" else "$this boot scripts"
}

/** One entry of the boot-script listing: `D|F <octal-perms> <owner> <path>`. */
data class BootEntry(val isDir: Boolean, val perms: String, val owner: String, val path: String) {
    val parent: String get() = path.substringBeforeLast('/', "")
    val name: String get() = path.substringAfterLast('/')

    /** Owned by a non-root user, or with the group- or other-write bit set. */
    val writableByOthers: Boolean
        get() = owner != "root" && owner != "0" || groupOrOtherWrite(perms)
}

object BootScripts {
    private val LINE = Regex("""^([DF])\s+([0-7]{3,4})\s+(\S+)\s+(/\S.*)$""")

    /** The entries in [text], in order; null when a non-blank line is not in the expected shape. */
    fun parse(text: String): List<BootEntry>? {
        val entries = ArrayList<BootEntry>()
        for (line in text.lines()) {
            if (line.isBlank()) continue
            val m = LINE.find(line.trim()) ?: return null
            entries += BootEntry(m.groupValues[1] == "D", m.groupValues[2], m.groupValues[3], m.groupValues[4])
        }
        return entries
    }
}

/** True when the group or other octal digit of [perms] (its last two) has the write bit (2). */
internal fun groupOrOtherWrite(perms: String): Boolean {
    val last3 = perms.takeLast(3)
    if (last3.length < 3) return false
    val group = last3[1].digitToIntOrNull(8) ?: return false
    val other = last3[2].digitToIntOrNull(8) ?: return false
    return group and 2 != 0 || other and 2 != 0
}
