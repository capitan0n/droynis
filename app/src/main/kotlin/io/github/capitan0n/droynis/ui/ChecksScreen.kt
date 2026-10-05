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
import androidx.compose.runtime.remember
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
    // Derived once per scan or filter change, not on every frame while the list scrolls.
    val verdicts = remember(findings) { findings.mapValues { it.value.verdict } }
    val counts = remember(catalog, verdicts) {
        CheckFilter.entries.associateWith { option -> catalog.count { option.matches(verdicts[it.id]) } }
    }
    val groups = remember(catalog, verdicts, filter, category) {
        Category.entries.mapNotNull { group ->
            val all = catalog.filter { it.category == group }
            val shown = all.filter { (category == null || group == category) && filter.matches(verdicts[it.id]) }
            if (shown.isEmpty()) null else CheckGroup(group, shown, all.count { verdicts[it.id] == Verdict.PASSED }, all.size)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(CHECKS_LIST_TAG),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        item(key = "legend", contentType = "legend") { LegendCard() }
        item(key = "filters", contentType = "chips") {
            FilterChips(counts, filter, onFilter, Modifier.padding(top = 8.dp))
        }
        item(key = "categories", contentType = "chips") {
            CategoryChips(category, onCategory, Modifier.padding(top = 5.dp))
        }

        if (groups.isEmpty()) {
            item(key = "empty", contentType = "empty") {
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

        for (group in groups) {
            item(key = "header-${group.category.name}", contentType = "header") {
                CategoryHeader(group.category, passed = group.passed, total = group.total)
            }
            itemsIndexed(group.specs, key = { _, spec -> spec.id }, contentType = { _, _ -> "check" }) { index, spec ->
                CheckRow(
                    spec = spec,
                    finding = findings[spec.id],
                    onClick = { onOpenCheck(spec.id) },
                    shape = groupShape(index, group.specs.size),
                )
            }
        }
    }
}

/** One category's visible checks, with pass counts over all of its checks. */
private class CheckGroup(val category: Category, val specs: List<CheckSpec>, val passed: Int, val total: Int)

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
    counts: Map<CheckFilter, Int>,
    selected: CheckFilter,
    onFilter: (CheckFilter) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        for (option in CheckFilter.entries) {
            val count = counts[option] ?: 0
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
private fun CategoryChips(selected: Category?, onCategory: (Category?) -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
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
