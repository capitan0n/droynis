package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status

/**
 * What a finding means for the user, in traffic-light terms: ✓ passed, – needs attention,
 * ✗ critical, ? unknown. The UI pairs each with an icon and a label, never color alone.
 */
enum class Verdict(val symbol: String, val label: String) {
    PASSED("✓", "Passed"),
    ATTENTION("–", "Needs attention"),
    CRITICAL("✗", "Critical"),
    UNKNOWN("?", "Unknown"),
    NOT_AVAILABLE("·", "Not available"),
}

val Finding.verdict: Verdict
    get() = when (status) {
        Status.PASS -> Verdict.PASSED
        Status.FAIL -> if (severity == Severity.CRITICAL) Verdict.CRITICAL else Verdict.ATTENTION
        Status.UNKNOWN -> Verdict.UNKNOWN
        Status.UNSUPPORTED -> Verdict.NOT_AVAILABLE
    }

fun List<Finding>.countByVerdict(): Map<Verdict, Int> =
    Verdict.entries.associateWith { verdict -> count { it.verdict == verdict } }

/** School-style grade for a hardening index score. */
enum class Grade(val minScore: Int, val label: String) {
    A(90, "Excellent"),
    B(75, "Good"),
    C(60, "Fair"),
    D(40, "Weak"),
    F(0, "At risk"),
    ;

    companion object {
        fun of(score: Int): Grade = entries.first { score >= it.minScore }
    }
}

val HardeningIndex.grade: Grade? get() = score?.let(Grade::of)
