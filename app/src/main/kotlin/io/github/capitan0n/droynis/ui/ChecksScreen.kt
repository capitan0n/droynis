package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.FilterAltOff
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.report.Verdict
import io.github.capitan0n.droynis.report.verdict

/** Every check with its ✓ – ✗ ? result, filterable by verdict and category. */
@Composable
fun ChecksScreen(
    catalog: List<CheckSpec>,
    findings: Map<String, Finding>,
    filter: CheckFilter,
    onFilter: (CheckFilter) -> Unit,
    category: Category?,
    onCategory: (Category?) -> Unit,
    onOpenCheck: (String) -> Unit,
) {
    val verdictOf = { spec: CheckSpec -> findings[spec.id]?.verdict }
    val visible = catalog.filter { (category == null || it.category == category) && filter.matches(verdictOf(it)) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(CHECKS_LIST_TAG),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                LegendCard()
                FilterChips(catalog, verdictOf, filter, onFilter)
                CategoryChips(category, onCategory)
            }
        }

        if (visible.isEmpty()) {
            item {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 40.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(stringResource(R.string.checks_empty), style = MaterialTheme.typography.bodyLarge)
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = {
                        onFilter(CheckFilter.ALL)
                        onCategory(null)
                    }) {
                        Icon(Icons.Rounded.FilterAltOff, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.clear_filters))
                    }
                }
            }
        }

        for (group in Category.entries) {
            val specs = visible.filter { it.category == group }
            if (specs.isEmpty()) continue
            item(key = "header-${group.name}") {
                val all = catalog.filter { it.category == group }
                CategoryHeader(group, passed = all.count { verdictOf(it) == Verdict.PASSED }, total = all.size)
            }
            itemsIndexed(specs, key = { _, spec -> spec.id }) { index, spec ->
                CheckRow(
                    spec = spec,
                    finding = findings[spec.id],
                    onClick = { onOpenCheck(spec.id) },
                    shape = groupShape(index, specs.size),
                )
            }
        }
    }
}

@Composable
private fun LegendCard() {
    ExpandableCard(
        title = stringResource(R.string.legend_title),
        leading = {
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                for (verdict in listOf(Verdict.PASSED, Verdict.ATTENTION, Verdict.CRITICAL)) {
                    VerdictIcon(verdict, size = 22.dp)
                }
            }
        },
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            for (verdict in VerdictDisplayOrder) LegendRow(verdict)
        }
    }
}

@Composable
fun LegendRow(verdict: Verdict) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        VerdictIcon(verdict, size = 24.dp)
        Spacer(Modifier.width(12.dp))
        Column {
            Text(stringResource(verdict.labelRes), style = MaterialTheme.typography.labelLarge)
            Text(
                stringResource(verdict.descriptionRes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun FilterChips(
    catalog: List<CheckSpec>,
    verdictOf: (CheckSpec) -> Verdict?,
    selected: CheckFilter,
    onFilter: (CheckFilter) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        for (option in CheckFilter.entries) {
            val count = catalog.count { option.matches(verdictOf(it)) }
            val label = when (option) {
                CheckFilter.ALL -> R.string.filter_all
                CheckFilter.ISSUES -> R.string.filter_issues
                CheckFilter.PASSED -> R.string.verdict_passed
                CheckFilter.ATTENTION -> R.string.verdict_short_attention
                CheckFilter.CRITICAL -> R.string.verdict_critical
                CheckFilter.UNVERIFIED -> R.string.stat_unverified
            }
            val icon = when (option) {
                CheckFilter.ALL, CheckFilter.ISSUES -> null
                CheckFilter.PASSED -> Verdict.PASSED
                CheckFilter.ATTENTION -> Verdict.ATTENTION
                CheckFilter.CRITICAL -> Verdict.CRITICAL
                CheckFilter.UNVERIFIED -> Verdict.UNKNOWN
            }
            FilterChip(
                selected = selected == option,
                onClick = { onFilter(option) },
                label = { Text("${stringResource(label)} $count") },
                leadingIcon = icon?.let { { VerdictIcon(it, size = 18.dp) } },
            )
        }
    }
}

@Composable
private fun CategoryChips(selected: Category?, onCategory: (Category?) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = selected == null,
            onClick = { onCategory(null) },
            label = { Text(stringResource(R.string.filter_all_categories)) },
            leadingIcon = { Icon(Icons.Rounded.Layers, contentDescription = null, modifier = Modifier.size(18.dp)) },
        )
        for (option in Category.entries) {
            FilterChip(
                selected = selected == option,
                onClick = { onCategory(if (selected == option) null else option) },
                label = { Text(stringResource(option.shortLabelRes)) },
                leadingIcon = {
                    Icon(option.icon, contentDescription = null, tint = option.accent, modifier = Modifier.size(18.dp))
                },
            )
        }
    }
}

@Composable
private fun CategoryHeader(category: Category, passed: Int, total: Int) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 4.dp, top = 18.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconBadge(category.icon, category.accent, size = 30.dp)
        Spacer(Modifier.width(10.dp))
        Text(stringResource(category.labelRes), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
        Text(
            stringResource(R.string.category_progress, passed, total),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
