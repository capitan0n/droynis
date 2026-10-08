package io.github.capitan0n.droynis.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.UiState
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.report.CategorySummary
import io.github.capitan0n.droynis.report.Verdict
import io.github.capitan0n.droynis.report.categorySummaries
import io.github.capitan0n.droynis.report.countByVerdict
import io.github.capitan0n.droynis.report.grade
import io.github.capitan0n.droynis.report.issues
import io.github.capitan0n.droynis.report.withoutMuted
import io.github.capitan0n.droynis.ui.theme.StatusColors
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@Composable
fun DashboardScreen(
    state: UiState,
    catalog: List<CheckSpec>,
    onScan: () -> Unit,
    onOpenCheck: (String) -> Unit,
    onShowChecks: (CheckFilter, Category?) -> Unit,
    onShowTools: () -> Unit,
) {
    // The first scan fills tiles and bars in live as checks finish. A rescan keeps the last result
    // on screen until it is complete, instead of emptying everything for a few seconds.
    // Muted checks are left out everywhere here, like in the score; derived once per change.
    val previous = state.result?.findings?.takeIf { state.scanning }
    val findings = remember(catalog, state.findings, previous, state.muted) {
        (previous ?: catalog.mapNotNull { state.findings[it.id] }).withoutMuted(state.muted)
    }
    val counts = remember(findings) { findings.countByVerdict() }
    val issues = remember(findings) { findings.issues() }
    val summaries = remember(catalog, findings, state.muted) {
        categorySummaries(catalog.filterNot { it.id in state.muted }, findings)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { HeroCard(state, issues.size, onScan) { onShowChecks(CheckFilter.MUTED, null) } }

        item { SectionHeader(stringResource(R.string.section_results)) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val tile = Modifier.weight(1f)
                StatTile(Verdict.PASSED, counts.getValue(Verdict.PASSED), stringResource(R.string.verdict_passed), tile) {
                    onShowChecks(CheckFilter.PASSED, null)
                }
                StatTile(
                    Verdict.ATTENTION,
                    counts.getValue(Verdict.ATTENTION),
                    stringResource(R.string.verdict_short_attention),
                    tile,
                ) { onShowChecks(CheckFilter.ATTENTION, null) }
                StatTile(Verdict.CRITICAL, counts.getValue(Verdict.CRITICAL), stringResource(R.string.verdict_critical), tile) {
                    onShowChecks(CheckFilter.CRITICAL, null)
                }
                StatTile(
                    Verdict.UNKNOWN,
                    counts.getValue(Verdict.UNKNOWN) + counts.getValue(Verdict.NOT_AVAILABLE),
                    stringResource(R.string.verdict_unknown),
                    tile,
                ) { onShowChecks(CheckFilter.UNVERIFIED, null) }
            }
        }

        item { SectionHeader(stringResource(R.string.section_categories)) }
        item(key = "categories", contentType = "categories") {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                for (row in summaries.chunked(2)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        for (summary in row) {
                            CategoryCard(summary, Modifier.weight(1f)) { onShowChecks(CheckFilter.ALL, summary.category) }
                        }
                        if (row.size == 1) Spacer(Modifier.weight(1f))
                    }
                }
            }
        }

        item {
            SectionHeader(
                title = stringResource(R.string.section_top_issues),
                action = if (issues.size > TOP_ISSUES) stringResource(R.string.see_all) else null,
                onAction = { onShowChecks(CheckFilter.ISSUES, null) },
            )
        }
        if (issues.isEmpty() && state.result != null) {
            item { AllClearCard() }
        } else {
            items(issues.take(TOP_ISSUES), key = { it.spec.id }, contentType = { "issue" }) { finding ->
                CheckRow(
                    spec = finding.spec,
                    finding = finding,
                    onClick = { onOpenCheck(finding.spec.id) },
                    shape = MaterialTheme.shapes.large,
                )
            }
        }

        item { SectionHeader(stringResource(R.string.section_your_device)) }
        item { DeviceCard(state, onShowTools) }
        item { PrivacyFooter() }
    }
}

private const val TOP_ISSUES = 4

@Composable
private fun HeroCard(state: UiState, issueCount: Int, onScan: () -> Unit, onShowMuted: () -> Unit) {
    val result = state.result
    val index = result?.index
    // Only the first scan shows its progress in the ring. A rescan keeps the last score there, and
    // its progress in the line below, until the new score is ready.
    val firstScan = result == null
    val target = if (firstScan) MaterialTheme.colorScheme.primary else index?.color ?: MaterialTheme.colorScheme.outline
    val color by animateColorAsState(target, animationSpec = tween(600), label = "heroColor")

    Card(
        shape = MaterialTheme.shapes.extraLarge,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .background(Brush.verticalGradient(listOf(color.copy(alpha = 0.22f), Color.Transparent))),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    stringResource(R.string.score_label),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                // The first scan has no score yet: the ring sweeps, with the logo where the score will
                // be, and the count of finished checks stays in the line below. A count in the ring read
                // like a score, and sat near the end while the slowest checks finished.
                RingGauge(fraction = if (firstScan) null else (index?.score ?: 0) / 100f, color = color) {
                    if (firstScan) {
                        Image(DroynisLogo, contentDescription = null, modifier = Modifier.size(72.dp))
                    } else {
                        val score = index?.score
                        val shown by animateIntAsState(score ?: 0, animationSpec = tween(1100), label = "score")
                        GaugeCenter(
                            big = if (score == null) stringResource(R.string.score_none) else "$shown",
                            small = stringResource(R.string.score_out_of),
                        )
                    }
                }
                val grade = index?.grade
                if (!firstScan && grade != null) {
                    Pill(
                        text = stringResource(R.string.grade_label, grade.name, stringResource(grade.labelRes)),
                        container = color.copy(alpha = 0.18f),
                        content = MaterialTheme.colorScheme.onSurface,
                    )
                }
                Spacer(Modifier.height(14.dp))
                Text(
                    text = when {
                        state.scanning || firstScan -> stringResource(R.string.headline_scanning)
                        index?.score == null -> stringResource(R.string.headline_no_score)
                        index.cappedBy.isNotEmpty() -> stringResource(R.string.headline_critical)
                        issueCount == 1 -> stringResource(R.string.headline_one_issue)
                        issueCount > 1 -> stringResource(R.string.headline_issues, issueCount)
                        else -> stringResource(R.string.headline_all_good)
                    },
                    style = MaterialTheme.typography.titleLarge,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = if (state.scanning || result == null) {
                        stringResource(R.string.scan_progress, state.done, state.total)
                    } else {
                        val time = result.context.startedAt.format(DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT))
                        stringResource(
                            R.string.scanned_at,
                            time,
                            result.findings.size,
                            stringResource(result.context.capabilities.tier.labelRes),
                        )
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                if (!firstScan && index?.cappedBy?.isNotEmpty() == true) {
                    Spacer(Modifier.height(10.dp))
                    val uncapped = index.uncappedScore
                    Pill(
                        text = if (uncapped != null && uncapped > (index.score ?: 0)) {
                            stringResource(R.string.capped_note_raw, uncapped)
                        } else {
                            stringResource(R.string.capped_note)
                        },
                        icon = Icons.Rounded.Warning,
                        maxLines = 2,
                        container = StatusColors.Critical.copy(alpha = 0.16f),
                        content = MaterialTheme.colorScheme.onSurface,
                    )
                }
                val muted = index?.muted.orEmpty()
                if (!firstScan && muted.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    Pill(
                        text = stringResource(R.string.muted_note, muted.size),
                        icon = Icons.Rounded.NotificationsOff,
                        modifier = Modifier.clip(CircleShape).clickable(onClick = onShowMuted),
                    )
                }
                Spacer(Modifier.height(18.dp))
                FilledTonalButton(onClick = onScan, enabled = !state.scanning) {
                    Icon(Icons.Rounded.Refresh, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                    Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                    Text(stringResource(R.string.menu_scan_again))
                }
            }
        }
    }
}

@Composable
private fun GaugeCenter(big: String, small: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(big, style = MaterialTheme.typography.displayLarge)
        Text(small, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun StatTile(verdict: Verdict, count: Int, label: String, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        modifier = modifier,
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier.padding(vertical = 14.dp, horizontal = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            VerdictIcon(verdict, size = 26.dp)
            Spacer(Modifier.height(6.dp))
            Text("$count", style = MaterialTheme.typography.headlineSmall)
            Text(
                label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun CategoryCard(summary: CategorySummary, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        modifier = modifier,
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconBadge(summary.category.icon, summary.category.accent, size = 38.dp)
                Spacer(Modifier.weight(1f))
                summary.worst?.let { VerdictIcon(it, size = 22.dp) }
            }
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(summary.category.shortLabelRes),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
            )
            Text(
                stringResource(R.string.category_progress, summary.passed, summary.total),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(10.dp))
            VerdictBar(summary.counts, total = summary.total)
        }
    }
}

@Composable
private fun AllClearCard() {
    Card(
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = StatusColors.Good.copy(alpha = 0.12f)),
    ) {
        Row(Modifier.fillMaxWidth().padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Rounded.CheckCircle, contentDescription = null, tint = StatusColors.Good, modifier = Modifier.size(32.dp))
            Spacer(Modifier.width(14.dp))
            Column {
                Text(stringResource(R.string.all_clear_title), style = MaterialTheme.typography.titleSmall)
                Text(
                    stringResource(R.string.all_clear_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun DeviceCard(state: UiState, onClick: () -> Unit) {
    val device = state.device
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            IconBadge(Icons.Rounded.PhoneAndroid, MaterialTheme.colorScheme.primary, size = 44.dp)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = device?.let { "${it.manufacturer} ${it.model}".trim() } ?: "…",
                    style = MaterialTheme.typography.titleSmall,
                )
                if (device != null) {
                    Text(
                        stringResource(R.string.device_android, device.androidVersion, device.sdkInt),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        stringResource(R.string.device_patch, device.securityPatch.ifEmpty { "?" }),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null)
        }
    }
}

@Composable
private fun PrivacyFooter() {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            Icons.Rounded.Lock,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
        Spacer(Modifier.width(10.dp))
        Text(
            stringResource(R.string.privacy_footer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
