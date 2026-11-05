package io.github.capitan0n.droynis.schedule

import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status

/** What one check showed in a scan. */
data class CheckState(val status: Status, val severity: Severity) {
    /** PASS or FAIL: the only results two scans can be compared on. */
    val scored: Boolean get() = status == Status.PASS || status == Status.FAIL
}

/**
 * The last known result of every check, kept between scans so a scheduled scan can tell what
 * changed. Only check ids, statuses and severities: no evidence, so nothing personal is stored.
 */
data class ScanSnapshot(
    /** Epoch milliseconds. */
    val takenAt: Long,
    val score: Int?,
    /** By check id, in catalog order. */
    val checks: Map<String, CheckState>,
) {
    /**
     * This scan on top of [previous]: a check that could not run now (Unknown or N/A, say because
     * Shizuku was not running) keeps its last PASS or FAIL, so the next scan compares against what
     * was last seen rather than against nothing. Checks that no longer exist are dropped.
     */
    fun carryingOver(previous: ScanSnapshot?): ScanSnapshot {
        if (previous == null) return this
        val merged = LinkedHashMap(checks)
        for ((id, now) in checks) {
            val before = previous.checks[id] ?: continue
            if (!now.scored && before.scored) merged[id] = before
        }
        return copy(checks = merged)
    }

    fun encode(): String = buildString {
        append(HEADER).append('\n')
        append("time ").append(takenAt).append('\n')
        append("score ").append(score?.toString() ?: "-").append('\n')
        for ((id, state) in checks) {
            append(id).append(' ').append(state.status.name).append(' ').append(state.severity.name).append('\n')
        }
    }

    companion object {
        private const val HEADER = "droynis-snapshot 1"

        fun of(findings: List<Finding>, score: Int?, takenAt: Long): ScanSnapshot = ScanSnapshot(
            takenAt = takenAt,
            score = score,
            checks = findings.associateTo(LinkedHashMap()) { it.spec.id to CheckState(it.status, it.severity) },
        )

        /**
         * Null for anything this version can't read; the next scan then starts afresh. A check that
         * moved to a new id is read under that id.
         */
        fun decode(text: String): ScanSnapshot? {
            val lines = text.lines().filter { it.isNotBlank() }
            if (lines.firstOrNull() != HEADER) return null
            var time: Long? = null
            var score: Int? = null
            val checks = LinkedHashMap<String, CheckState>()
            for (line in lines.drop(1)) {
                val parts = line.split(' ')
                when {
                    parts.size == 2 && parts[0] == "time" -> time = parts[1].toLongOrNull()
                    parts.size == 2 && parts[0] == "score" -> score = parts[1].toIntOrNull()
                    parts.size == 3 -> {
                        val status = Status.entries.firstOrNull { it.name == parts[1] } ?: continue
                        val severity = Severity.entries.firstOrNull { it.name == parts[2] } ?: continue
                        checks[CheckSpec.currentId(parts[0])] = CheckState(status, severity)
                    }
                }
            }
            return ScanSnapshot(time ?: return null, score, checks)
        }
    }
}

/** What changed between two scans, counting only checks that both could score. */
data class ScanChanges(
    /** Checks that passed before and fail now, or fail more severely now; most severe first. */
    val newIssues: List<String>,
    /** Checks that failed before and pass now. */
    val fixed: List<String>,
    /** Checks that were scored before but could not run this time. */
    val notRun: List<String>,
) {
    /** Something that passed now fails: the case a notification is always worth it for. */
    val worse: Boolean get() = newIssues.isNotEmpty()

    companion object {
        val NONE = ScanChanges(emptyList(), emptyList(), emptyList())

        /**
         * Muted checks are left out, like in the score. A check that was not scored before (it is
         * new, or its tier was not available) is never a new issue: there is nothing to compare.
         */
        fun between(before: ScanSnapshot?, now: ScanSnapshot, muted: Set<String>): ScanChanges {
            if (before == null) return NONE
            val newIssues = mutableListOf<Pair<String, Severity>>()
            val fixed = mutableListOf<String>()
            val notRun = mutableListOf<String>()
            for ((id, current) in now.checks) {
                if (id in muted) continue
                val previous = before.checks[id] ?: continue
                when {
                    current.status == Status.FAIL && previous.status == Status.PASS -> newIssues += id to current.severity
                    current.status == Status.FAIL && previous.status == Status.FAIL && current.severity > previous.severity ->
                        newIssues += id to current.severity
                    current.status == Status.PASS && previous.status == Status.FAIL -> fixed += id
                    !current.scored && previous.scored -> notRun += id
                }
            }
            return ScanChanges(newIssues.sortedByDescending { it.second }.map { it.first }, fixed, notRun)
        }
    }
}
