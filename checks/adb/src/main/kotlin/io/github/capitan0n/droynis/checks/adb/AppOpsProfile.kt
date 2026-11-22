package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.core.Reading

/** Keep only this app's Android user's UID blocks before either AppOps parser sees the dump. */
fun appOpsForProfile(dump: Reading.Value<String>, appUid: Int): Reading<String> {
    val source = dump.source.copy(method = "${dump.source.method} (current profile)")
    val lines = dump.value.lineSequence()
    // Older releases have no section heading. Other sections may also mention UIDs.
    val section = if (SECTION in dump.value) {
        lines.dropWhile { it.trim() != SECTION }.drop(1)
    } else {
        lines.dropWhile { !it.isUidHeader() }
    }

    val result = StringBuilder()
    var keep: Boolean? = null
    for (line in section) {
        if (line.isEmpty()) continue
        if (!line.first().isWhitespace()) break
        if (line.isUidHeader()) {
            // Bound the only regex match. An unfamiliar UID must never inherit the previous profile.
            val header = if (line.length <= 80) UID_HEADER.matchEntire(line.trim()) else null
            val user = header?.let {
                val numeric = it.groupValues[1]
                if (numeric.isEmpty()) it.groupValues[2].toIntOrNull() else numeric.toIntOrNull()?.div(PER_USER_RANGE)
            } ?: return Reading.Unavailable("unrecognized app-ops UID header", source)
            keep = user == appUid / PER_USER_RANGE
        } else if (keep == null && line.isNotBlank()) {
            return Reading.Unavailable("app-ops data before the first UID", source)
        }
        if (keep == true) result.appendLine(line)
    }
    if (result.isEmpty()) return Reading.Unavailable("no app-ops UID records for this profile", source)
    return Reading.Value(result.toString(), source)
}

// Treat an unfamiliar UID heading as a block boundary too, so malformed records cannot cross profiles.
private fun String.isUidHeader() = startsAfterIndent("Uid ") || startsAfterIndent("Uid\t") || startsAfterIndent("Uid:")

private const val SECTION = "AppOps Uid Op State"
private const val PER_USER_RANGE = 100_000
// UserHandle.formatUid includes app, system, isolated and app-zygote isolated UIDs.
private val UID_HEADER = Regex("""Uid (?:([0-9]+)|u([0-9]+)(?:ai|[asi])[0-9]+):""")
