package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.count
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
import java.time.Instant
import java.time.ZoneOffset

/**
 * Programs staged in `/data/local/tmp`, the one folder a computer with adb (or a Shizuku app) can
 * write without root. Scripts and executables left there are a small risk on their own, but a real
 * one when root runs them: the folder and its files belong to the `shell` user, so anything running
 * as `shell` can rewrite a file between the moment you check it and the moment root runs it.
 */
class TempFilesCheck(private val shell: RootShellProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1303",
        category = Category.DEVICE_INTEGRITY,
        title = "Programs staged in shared temp",
        severity = Severity.NOTICE,
        explanation = "/data/local/tmp is where a computer with adb, or an app using Shizuku, drops files, since " +
            "it is the one place they can write without root. Scripts or executables sitting there are often " +
            "left over from setup or testing. They matter most if you ever run them as root: the folder is " +
            "owned by the shell user, so adb or a Shizuku app can replace a file there before root runs it.",
        remediation = Remediation(
            text = "Remove what you no longer need from /data/local/tmp. For anything you do run as root, move it " +
                "somewhere only root can write (for example /data/adb) and set it to `chown root:root` and " +
                "`chmod 700` first, so the shell user can't change it under you.",
        ),
        requires = setOf(Grant.ROOT),
        failsWhen = "a script or executable is staged in /data/local/tmp",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val reading = shell.tempFiles()
        return reading.evaluate("The contents of /data/local/tmp", listOf(reading.toEvidence("/data/local/tmp"))) { raw ->
            val entries = TempFiles.parse(raw)
                ?: return@evaluate Outcome.unknown(
                    "The /data/local/tmp listing was not in the expected format",
                    listOf(Evidence("/data/local/tmp", "unexpected format", reading.source)),
                )
            val runnable = entries.filter { it.runnable }
            val evidence = runnable.map { entry ->
                Evidence(
                    "Staged program",
                    "${entry.path} (${entry.perms} ${entry.owner}, ${entry.date()})",
                    reading.source,
                    note = if (entry.worldWritable) "world-writable: anyone on the phone can replace it" else null,
                )
            }
            if (runnable.isEmpty()) {
                return@evaluate Outcome.pass("Nothing runnable is staged in /data/local/tmp", evidence)
            }
            val writable = runnable.count { it.worldWritable }
            val extra = if (writable > 0) ", ${count(writable, "of them world-writable", "of them world-writable")}" else ""
            Outcome.fail(
                "${count(runnable.size, "program")} staged in /data/local/tmp: ${runnable.map { it.name }.joinNames()}$extra",
                evidence,
            )
        }
    }
}

/** One entry of the temp listing: `D|F <octal-perms> <owner> <size> <mtime-epoch> <path>`. */
data class TempEntry(
    val isDir: Boolean,
    val perms: String,
    val owner: String,
    val size: Long,
    val mtimeEpoch: Long,
    val path: String,
) {
    val name: String get() = path.substringAfterLast('/')

    val worldWritable: Boolean get() = groupOrOtherWrite(perms)

    /** A non-directory that is executable, or named like a shell script. */
    val runnable: Boolean get() = !isDir && (anyExecBit(perms) || name.endsWith(".sh"))

    fun date(): String = Instant.ofEpochSecond(mtimeEpoch).atZone(ZoneOffset.UTC).toLocalDate().toString()
}

object TempFiles {
    private val LINE = Regex("""^([DF])\s+([0-7]{3,4})\s+(\S+)\s+(\d+)\s+(\d+)\s+(/\S.*)$""")

    /** The entries in [text], in order; null when a non-blank line is not in the expected shape. */
    fun parse(text: String): List<TempEntry>? {
        val entries = ArrayList<TempEntry>()
        for (line in text.lines()) {
            if (line.isBlank()) continue
            val m = LINE.find(line.trim()) ?: return null
            entries += TempEntry(
                isDir = m.groupValues[1] == "D",
                perms = m.groupValues[2],
                owner = m.groupValues[3],
                size = m.groupValues[4].toLong(),
                mtimeEpoch = m.groupValues[5].toLong(),
                path = m.groupValues[6],
            )
        }
        return entries
    }
}

/** True when any of the owner/group/other octal digits of [perms] (its last three) has the execute bit (1). */
internal fun anyExecBit(perms: String): Boolean {
    val last3 = perms.takeLast(3)
    if (last3.length < 3) return false
    return last3.any { (it.digitToIntOrNull(8) ?: 0) and 1 != 0 }
}
