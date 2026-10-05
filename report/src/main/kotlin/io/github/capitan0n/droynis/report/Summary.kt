package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Status

/** Tallies for one category of a scan, for dashboards. */
data class CategorySummary(
    val category: Category,
    val total: Int,
    val counts: Map<Verdict, Int>,
) {
    val passed: Int get() = count(Verdict.PASSED)
    val issues: Int get() = count(Verdict.ATTENTION) + count(Verdict.CRITICAL)

    /** Checks that produced PASS or FAIL, the only ones that are scored. */
    val scored: Int get() = passed + issues

    /** The worst scored verdict, or null when nothing in the category could be scored. */
    val worst: Verdict?
        get() = listOf(Verdict.CRITICAL, Verdict.ATTENTION, Verdict.PASSED).firstOrNull { count(it) > 0 }

    fun count(verdict: Verdict): Int = counts[verdict] ?: 0
}

/**
 * One summary per category that has checks in [specs], in category order. [findings] may be
 * partial while a scan runs: [CategorySummary.total] still counts every check.
 */
fun categorySummaries(specs: List<CheckSpec>, findings: List<Finding>): List<CategorySummary> =
    Category.entries.mapNotNull { category ->
        val total = specs.count { it.category == category }
        if (total == 0) {
            null
        } else {
            CategorySummary(category, total, findings.filter { it.spec.category == category }.countByVerdict())
        }
    }

/**
 * The findings the score counts: all but the checks the user muted. Muted checks still run and
 * keep their result; they just don't count.
 */
fun List<Finding>.withoutMuted(muted: Collection<String>): List<Finding> =
    if (muted.isEmpty()) this else filterNot { it.spec.id in muted }

/** Failed checks, most severe first; equally severe ones keep their order. */
fun List<Finding>.issues(): List<Finding> =
    filter { it.status == Status.FAIL }.sortedByDescending { it.severity }
