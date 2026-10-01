package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.ScanState
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.report.HardeningIndex

const val FINDINGS_LIST_TAG = "findings"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    state: ScanState,
    onRescan: () -> Unit,
    onOpenSettings: (List<String>) -> Unit,
) {
    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.app_name)) }) },
    ) { padding ->
        when (state) {
            is ScanState.Scanning -> ScanProgress(state, Modifier.padding(padding))
            is ScanState.Done -> ReportList(state, onRescan, onOpenSettings, Modifier.padding(padding))
        }
    }
}

@Composable
private fun ScanProgress(state: ScanState.Scanning, modifier: Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.scanning, state.done, state.total))
    }
}

@Composable
private fun ReportList(
    state: ScanState.Done,
    onRescan: () -> Unit,
    onOpenSettings: (List<String>) -> Unit,
    modifier: Modifier,
) {
    val byCategory = state.findings.groupBy { it.spec.category }
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .testTag(FINDINGS_LIST_TAG),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "score") {
            ScoreCard(state.index, state.context.capabilities.tier.name, onRescan)
        }
        for (category in Category.entries) {
            val findings = byCategory[category] ?: continue
            item(key = category.name) {
                Text(
                    text = category.label,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            items(findings, key = { it.spec.id }) { finding ->
                FindingCard(finding, onOpenSettings)
            }
        }
    }
}

@Composable
private fun ScoreCard(index: HardeningIndex, tier: String, onRescan: () -> Unit) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.hardening_index), style = MaterialTheme.typography.labelLarge)
            Row(verticalAlignment = Alignment.Bottom) {
                Text(index.score?.toString() ?: "–", style = MaterialTheme.typography.displayMedium)
                Text(
                    text = stringResource(R.string.score_out_of),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(start = 4.dp, bottom = 8.dp),
                )
            }
            if (index.score == null) {
                Text(stringResource(R.string.score_none))
            }
            if (index.cappedBy.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.score_capped, HardeningIndex.CRITICAL_CAP, index.cappedBy.joinToString()),
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Text(
                stringResource(
                    R.string.failed_counts,
                    index.failed[Severity.CRITICAL] ?: 0,
                    index.failed[Severity.WARNING] ?: 0,
                    index.failed[Severity.NOTICE] ?: 0,
                ),
            )
            Text(stringResource(R.string.evaluated_skipped, index.evaluated, index.skipped))
            Text(stringResource(R.string.active_tier, tier))
            Button(onClick = onRescan) { Text(stringResource(R.string.rescan)) }
        }
    }
}

@Composable
private fun FindingCard(finding: Finding, onOpenSettings: (List<String>) -> Unit) {
    var expanded by rememberSaveable(finding.spec.id) { mutableStateOf(false) }
    OutlinedCard(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(
                    onClickLabel = stringResource(if (expanded) R.string.hide_details else R.string.show_details),
                ) { expanded = !expanded }
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            StatusBadge(finding)
            Column(
                Modifier
                    .padding(start = 12.dp)
                    .weight(1f),
            ) {
                Text(finding.spec.title, style = MaterialTheme.typography.titleSmall)
                Text(
                    text = finding.summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (expanded) {
            Column(
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                FindingDetails(finding, onOpenSettings)
            }
        }
    }
}

@Composable
private fun StatusBadge(finding: Finding) {
    val colors = MaterialTheme.colorScheme
    val (label, container) = when (finding.status) {
        Status.PASS -> stringResource(R.string.status_pass) to colors.primaryContainer
        Status.FAIL -> severityLabel(finding.severity) to
            if (finding.severity >= Severity.WARNING) colors.errorContainer else colors.tertiaryContainer
        Status.UNKNOWN -> stringResource(R.string.status_unknown) to colors.surfaceVariant
        Status.UNSUPPORTED -> stringResource(R.string.status_unsupported) to colors.surfaceVariant
    }
    Surface(color = container, shape = MaterialTheme.shapes.small) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun severityLabel(severity: Severity): String = stringResource(
    when (severity) {
        Severity.CRITICAL -> R.string.severity_critical
        Severity.WARNING -> R.string.severity_warning
        Severity.NOTICE -> R.string.severity_notice
        Severity.INFO -> R.string.severity_info
    },
)

@Composable
private fun FindingDetails(finding: Finding, onOpenSettings: (List<String>) -> Unit) {
    val spec = finding.spec
    HorizontalDivider()
    Section(stringResource(R.string.why_it_matters)) {
        Text(spec.explanation, style = MaterialTheme.typography.bodyMedium)
    }
    Section(stringResource(R.string.evidence)) {
        if (finding.evidence.isEmpty()) {
            Text(stringResource(R.string.no_evidence), style = MaterialTheme.typography.bodyMedium)
        }
        for (item in finding.evidence) {
            SelectionContainer {
                Text(
                    text = "${item.label}: ${item.value ?: "—"}",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                )
            }
            Text(
                text = stringResource(R.string.evidence_source, item.source.toString()) +
                    (item.note?.let { " · $it" } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    if (finding.status == Status.FAIL || finding.status == Status.UNKNOWN) {
        Section(stringResource(R.string.what_you_can_do)) {
            Text(spec.remediation.text, style = MaterialTheme.typography.bodyMedium)
            spec.remediation.command?.let { command ->
                SelectionContainer { Text(command, fontFamily = FontFamily.Monospace) }
            }
            if (spec.remediation.settingsActions.isNotEmpty()) {
                FilledTonalButton(onClick = { onOpenSettings(spec.remediation.settingsActions) }) {
                    Text(stringResource(R.string.open_settings))
                }
            }
        }
    }
    Text(
        text = stringResource(R.string.check_meta, spec.id, spec.requiredTier.name, finding.elapsedMillis),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.labelLarge)
        content()
    }
}
