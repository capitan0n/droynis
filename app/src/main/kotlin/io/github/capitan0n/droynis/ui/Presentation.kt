package io.github.capitan0n.droynis.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.QuestionMark
import androidx.compose.material.icons.rounded.Remove
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.report.Grade
import io.github.capitan0n.droynis.report.HardeningIndex
import io.github.capitan0n.droynis.report.Verdict
import io.github.capitan0n.droynis.report.grade
import io.github.capitan0n.droynis.ui.theme.StatusColors
import io.github.capitan0n.droynis.ui.theme.isDarkTheme

/** How a verdict looks: a colored disc with a glyph, always next to a text label. */
@Immutable
data class VerdictStyle(val color: Color, val onColor: Color, val icon: ImageVector)

val Verdict.style: VerdictStyle
    @Composable get() = when (this) {
        Verdict.PASSED -> VerdictStyle(StatusColors.Good, StatusColors.OnGood, Icons.Rounded.Check)
        Verdict.ATTENTION -> VerdictStyle(StatusColors.Warning, StatusColors.OnWarning, Icons.Rounded.Remove)
        Verdict.CRITICAL -> VerdictStyle(StatusColors.Critical, StatusColors.OnCritical, Icons.Rounded.Close)
        Verdict.UNKNOWN -> VerdictStyle(
            MaterialTheme.colorScheme.outline,
            MaterialTheme.colorScheme.surface,
            Icons.Rounded.QuestionMark,
        )
        Verdict.NOT_AVAILABLE -> VerdictStyle(
            MaterialTheme.colorScheme.outlineVariant,
            MaterialTheme.colorScheme.onSurfaceVariant,
            Icons.Rounded.Block,
        )
    }

val Verdict.labelRes: Int
    get() = when (this) {
        Verdict.PASSED -> R.string.verdict_passed
        Verdict.ATTENTION -> R.string.verdict_attention
        Verdict.CRITICAL -> R.string.verdict_critical
        Verdict.UNKNOWN -> R.string.verdict_unknown
        Verdict.NOT_AVAILABLE -> R.string.verdict_not_available
    }

/** Shorter label for chips and tiles. */
val Verdict.shortLabelRes: Int
    get() = when (this) {
        Verdict.ATTENTION -> R.string.verdict_short_attention
        Verdict.NOT_AVAILABLE -> R.string.verdict_short_not_available
        else -> labelRes
    }

val Verdict.descriptionRes: Int
    get() = when (this) {
        Verdict.PASSED -> R.string.verdict_desc_passed
        Verdict.ATTENTION -> R.string.verdict_desc_attention
        Verdict.CRITICAL -> R.string.verdict_desc_critical
        Verdict.UNKNOWN -> R.string.verdict_desc_unknown
        Verdict.NOT_AVAILABLE -> R.string.verdict_desc_not_available
    }

val Severity.labelRes: Int
    get() = when (this) {
        Severity.CRITICAL -> R.string.severity_critical
        Severity.WARNING -> R.string.severity_warning
        Severity.NOTICE -> R.string.severity_notice
        Severity.INFO -> R.string.severity_info
    }

val Category.labelRes: Int
    get() = when (this) {
        Category.DEVICE_INTEGRITY -> R.string.category_integrity
        Category.ACCESS_CONTROL -> R.string.category_access
        Category.APPS -> R.string.category_apps
        Category.NETWORK -> R.string.category_network
    }

val Category.shortLabelRes: Int
    get() = when (this) {
        Category.DEVICE_INTEGRITY -> R.string.category_short_integrity
        Category.ACCESS_CONTROL -> R.string.category_short_access
        Category.APPS -> R.string.category_short_apps
        Category.NETWORK -> R.string.category_short_network
    }

val Category.icon: ImageVector
    get() = when (this) {
        Category.DEVICE_INTEGRITY -> Icons.Rounded.VerifiedUser
        Category.ACCESS_CONTROL -> Icons.Rounded.Lock
        Category.APPS -> Icons.Rounded.Apps
        Category.NETWORK -> Icons.Rounded.Wifi
    }

/** One accent per category, used for its icon only so it never reads as a status. */
val Category.accent: Color
    @Composable get() {
        val dark = isDarkTheme
        return when (this) {
            Category.DEVICE_INTEGRITY -> if (dark) Color(0xFF3987E5) else Color(0xFF2A78D6)
            Category.ACCESS_CONTROL -> if (dark) Color(0xFF9085E9) else Color(0xFF4A3AA7)
            Category.APPS -> Color(0xFFD55181)
            Category.NETWORK -> Color(0xFF199E70)
        }
    }

val Grade.labelRes: Int
    get() = when (this) {
        Grade.A -> R.string.grade_a
        Grade.B -> R.string.grade_b
        Grade.C -> R.string.grade_c
        Grade.D -> R.string.grade_d
        Grade.F -> R.string.grade_f
    }

/** Traffic-light color of a grade: green for A and B, yellow for C and D, red for F. */
val Grade.color: Color
    get() = when (this) {
        Grade.A, Grade.B -> StatusColors.Good
        Grade.C, Grade.D -> StatusColors.Warning
        Grade.F -> StatusColors.Critical
    }

/** A score capped by a critical failure is red whatever its grade. */
val HardeningIndex.color: Color?
    get() = when {
        cappedBy.isNotEmpty() -> StatusColors.Critical
        else -> grade?.color
    }

/** Order of verdicts in legends, filters and bars. */
val VerdictDisplayOrder = listOf(Verdict.PASSED, Verdict.ATTENTION, Verdict.CRITICAL, Verdict.UNKNOWN, Verdict.NOT_AVAILABLE)
