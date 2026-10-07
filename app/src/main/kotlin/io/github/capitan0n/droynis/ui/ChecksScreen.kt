package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.FilterAltOff
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.report.Verdict
import io.github.capitan0n.droynis.report.verdict

/** Every check with its ✓ – ✗ ? result, searchable and filterable by verdict, category and privilege tier. */
@Composable
fun ChecksScreen(
    catalog: List<CheckSpec>,
    findings: Map<String, Finding>,
    muted: Set<String>,
    query: String,
    onQuery: (String) -> Unit,
    filter: CheckFilter,
    onFilter: (CheckFilter) -> Unit,
    category: Category?,
    onCategory: (Category?) -> Unit,
    tier: Tier?,
    onTier: (Tier?) -> Unit,
    onOpenCheck: (String) -> Unit,
    onUnmuteAll: () -> Unit,
) {
    // Derived once per scan or filter change, not on every frame while the list scrolls.
    val verdicts = remember(findings) { findings.mapValues { it.value.verdict } }
    // Tiers with at least one check; Shizuku and root chips appear once they have checks.
    val tiers = remember(catalog) { catalog.map { it.requiredTier }.distinct().sorted() }
    // Built once per scan, so typing only compares strings.
    val searchTexts = remember(catalog, findings) { catalog.associate { it.id to searchText(it, findings[it.id]) } }
    val words = remember(query) { searchWords(query) }
    // What the search, category and tier leave; the verdict chips count within it.
    val scope = remember(catalog, searchTexts, words, category, tier) {
        catalog.filter {
            (category == null || it.category == category) &&
                (tier == null || it.requiredTier == tier) &&
                matchesSearch(searchTexts.getValue(it.id), words)
        }
    }
    val counts = remember(scope, verdicts, muted) {
        CheckFilter.entries.associateWith { option ->
            scope.count { option.matches(verdicts[it.id], it.id in muted) }
        }
    }
    val groups = remember(catalog, scope, verdicts, muted, filter, tier) {
        Category.entries.mapNotNull { group ->
            val shown = scope.filter { it.category == group && filter.matches(verdicts[it.id], it.id in muted) }
            if (shown.isEmpty()) return@mapNotNull null
            // Over the whole category, and like the score, without muted checks.
            val scored = catalog.filter {
                it.category == group && (tier == null || it.requiredTier == tier) && it.id !in muted
            }
            CheckGroup(group, shown, scored.count { verdicts[it.id] == Verdict.PASSED }, scored.size)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(CHECKS_LIST_TAG),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        item(key = "search", contentType = "search") { SearchField(query, onQuery) }
        item(key = "legend", contentType = "legend") { LegendCard(Modifier.padding(top = 8.dp)) }
        item(key = "filters", contentType = "chips") {
            FilterChips(counts, filter, onFilter, Modifier.padding(top = 8.dp))
        }
        item(key = "categories", contentType = "chips") {
            CategoryChips(category, onCategory, Modifier.padding(top = 5.dp))
        }
        if (tiers.size > 1) {
            item(key = "tiers", contentType = "chips") {
                TierChips(tiers, tier, onTier, Modifier.padding(top = 5.dp))
            }
        }
        if (filter == CheckFilter.MUTED && muted.isNotEmpty()) {
            item(key = "unmute", contentType = "unmute") { UnmuteAllRow(onUnmuteAll, Modifier.padding(top = 10.dp)) }
        }

        if (groups.isEmpty()) {
            item(key = "empty", contentType = "empty") {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 40.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    val filtered = filter != CheckFilter.ALL || category != null || tier != null
                    Text(
                        if (words.isEmpty()) {
                            stringResource(R.string.checks_empty)
                        } else {
                            stringResource(R.string.checks_no_match, query.trim())
                        },
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = {
                        onQuery("")
                        onFilter(CheckFilter.ALL)
                        onCategory(null)
                        onTier(null)
                    }) {
                        Icon(Icons.Rounded.FilterAltOff, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            stringResource(
                                when {
                                    words.isEmpty() -> R.string.clear_filters
                                    filtered -> R.string.clear_search_and_filters
                                    else -> R.string.clear_search
                                },
                            ),
                        )
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
                    muted = spec.id in muted,
                )
            }
        }
    }
}

/** One category's visible checks, with pass counts over all of its checks. */
private class CheckGroup(val category: Category, val specs: List<CheckSpec>, val passed: Int, val total: Int)

/** Shown above the muted checks: what muting does, and a way to undo it for all of them at once. */
@Composable
private fun UnmuteAllRow(onUnmuteAll: () -> Unit, modifier: Modifier = Modifier) {
    var confirm by rememberSaveable { mutableStateOf(false) }
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Row(
            modifier = Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                Icons.Rounded.NotificationsOff,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(12.dp))
            Text(
                stringResource(R.string.muted_explained),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { confirm = true }) { Text(stringResource(R.string.unmute_all)) }
        }
    }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            icon = { Icon(Icons.Rounded.NotificationsActive, contentDescription = null) },
            title = { Text(stringResource(R.string.unmute_all_title)) },
            text = { Text(stringResource(R.string.unmute_all_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    onUnmuteAll()
                }) { Text(stringResource(R.string.unmute)) }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/** A compact search pill: smaller than a Material text field, so the filters stay in view. */
@Composable
private fun SearchField(query: String, onQuery: (String) -> Unit, modifier: Modifier = Modifier) {
    val focus = LocalFocusManager.current
    val interaction = remember { MutableInteractionSource() }
    val focused by interaction.collectIsFocusedAsState()
    val colors = MaterialTheme.colorScheme
    BasicTextField(
        value = query,
        onValueChange = onQuery,
        modifier = modifier.fillMaxWidth().testTag(CHECKS_SEARCH_TAG),
        singleLine = true,
        textStyle = MaterialTheme.typography.bodyMedium.copy(color = colors.onSurface),
        cursorBrush = SolidColor(colors.primary),
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
        // The list updates while typing; Search only puts the keyboard away.
        keyboardActions = KeyboardActions(onSearch = { focus.clearFocus() }),
        interactionSource = interaction,
        decorationBox = { field ->
            Row(
                modifier = Modifier
                    .height(44.dp)
                    .clip(CircleShape)
                    .background(colors.surfaceContainerLow)
                    .border(if (focused) 2.dp else 1.dp, if (focused) colors.primary else colors.outlineVariant, CircleShape)
                    .padding(start = 14.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    Icons.Rounded.Search,
                    contentDescription = null,
                    tint = colors.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(10.dp))
                Box(Modifier.weight(1f)) {
                    if (query.isEmpty()) {
                        Text(
                            stringResource(R.string.checks_search_hint),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    field()
                }
                if (query.isEmpty()) {
                    Spacer(Modifier.width(10.dp))
                } else {
                    IconButton(onClick = { onQuery("") }, modifier = Modifier.size(36.dp)) {
                        Icon(
                            Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.clear_search),
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
            }
        },
    )
}

@Composable
private fun LegendCard(modifier: Modifier = Modifier) {
    ExpandableCard(
        title = stringResource(R.string.legend_title),
        modifier = modifier,
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
            // The Muted chip appears once something is muted.
            if (option == CheckFilter.MUTED && count == 0 && selected != option) continue
            val label = when (option) {
                CheckFilter.ALL -> R.string.filter_all
                CheckFilter.ISSUES -> R.string.filter_issues
                CheckFilter.PASSED -> R.string.verdict_passed
                CheckFilter.ATTENTION -> R.string.verdict_short_attention
                CheckFilter.CRITICAL -> R.string.verdict_critical
                CheckFilter.UNVERIFIED -> R.string.stat_unverified
                CheckFilter.MUTED -> R.string.muted
            }
            val icon = when (option) {
                CheckFilter.ALL, CheckFilter.ISSUES, CheckFilter.MUTED -> null
                CheckFilter.PASSED -> Verdict.PASSED
                CheckFilter.ATTENTION -> Verdict.ATTENTION
                CheckFilter.CRITICAL -> Verdict.CRITICAL
                CheckFilter.UNVERIFIED -> Verdict.UNKNOWN
            }
            FilterChip(
                selected = selected == option,
                onClick = { onFilter(option) },
                label = { Text("${stringResource(label)} $count") },
                leadingIcon = when {
                    icon != null -> {
                        { VerdictIcon(icon, size = 18.dp) }
                    }
                    option == CheckFilter.MUTED -> {
                        { Icon(Icons.Rounded.NotificationsOff, contentDescription = null, modifier = Modifier.size(18.dp)) }
                    }
                    else -> null
                },
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
private fun TierChips(tiers: List<Tier>, selected: Tier?, onTier: (Tier?) -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = selected == null,
            onClick = { onTier(null) },
            label = { Text(stringResource(R.string.filter_all_tiers)) },
            leadingIcon = { Icon(Icons.Rounded.Layers, contentDescription = null, modifier = Modifier.size(18.dp)) },
        )
        for (option in tiers) {
            FilterChip(
                selected = selected == option,
                onClick = { onTier(if (selected == option) null else option) },
                label = { Text(stringResource(option.labelRes)) },
                leadingIcon = { Icon(option.icon, contentDescription = null, modifier = Modifier.size(18.dp)) },
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
