package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status

/**
 * Hardening index of one scan.
 *
 * Only PASS and FAIL count. Each check weighs by its declared severity, so a result can't change
 * its own weight; an escalated (effective) CRITICAL FAIL still caps the score at [CRITICAL_CAP].
 * The score is floored, so any failure keeps it below 100.
 */
data class HardeningIndex(
    /** 0–100, or null when no weighted check produced PASS or FAIL. */
    val score: Int?,
    /** The score before the critical cap; equal to [score] when nothing capped it. */
    val uncappedScore: Int?,
    val passed: Int,
    /** FAIL counts by effective severity. */
    val failed: Map<Severity, Int>,
    val unknown: Int,
    val unsupported: Int,
    /** Ids of CRITICAL failures that capped the score. */
    val cappedBy: List<String>,
) {
    val evaluated: Int get() = passed + failed.values.sum()
    val skipped: Int get() = unknown + unsupported

    companion object {
        const val CRITICAL_CAP = 40

        fun weight(severity: Severity): Int = when (severity) {
            Severity.CRITICAL -> 10
            Severity.WARNING -> 5
            Severity.NOTICE -> 2
            Severity.INFO -> 0
        }

        fun of(findings: List<Finding>): HardeningIndex {
            val passed = findings.filter { it.status == Status.PASS }
            val failed = findings.filter { it.status == Status.FAIL }
            val total = (passed + failed).sumOf { weight(it.spec.severity) }
            val earned = passed.sumOf { weight(it.spec.severity) }
            val cappedBy = failed.filter { it.severity == Severity.CRITICAL }.map { it.spec.id }
            val raw = if (total == 0) null else earned * 100 / total
            return HardeningIndex(
                score = raw?.let { if (cappedBy.isEmpty()) it else minOf(it, CRITICAL_CAP) },
                uncappedScore = raw,
                passed = passed.size,
                failed = failed.groupingBy { it.severity }.eachCount(),
                unknown = findings.count { it.status == Status.UNKNOWN },
                unsupported = findings.count { it.status == Status.UNSUPPORTED },
                cappedBy = cappedBy,
            )
        }
    }
}
