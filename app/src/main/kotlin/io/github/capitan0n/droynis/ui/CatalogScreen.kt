package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.platform.shizuku.ShizukuStatus
import io.github.capitan0n.droynis.report.verdict
import androidx.compose.material3.Tab as MaterialTab

/**
 * Every check, one tab per privilege tier. Each tab starts with what the tier is and how to set it
 * up, then lists its checks by category, each with a mute switch.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CatalogScreen(
    catalog: List<CheckSpec>,
    findings: Map<String, Finding>,
    muted: Set<String>,
    grants: Set<Grant>,
    shizuku: ShizukuStatus?,
    selected: Tier,
    onSelect: (Tier) -> Unit,
    scanning: Boolean,
    actions: AppActions,
    onOpenCheck: (String) -> Unit,
) {
    val byTier = remember(catalog) { catalog.groupBy { it.requiredTier } }
    Column(Modifier.fillMaxSize()) {
        PrimaryTabRow(selectedTabIndex = selected.ordinal) {
            for (tier in Tier.entries) {
                MaterialTab(
                    selected = tier == selected,
                    onClick = { onSelect(tier) },
                    text = { Text(stringResource(tier.labelRes)) },
                )
            }
        }

        val specs = byTier[selected].orEmpty()
        val needed = remember(specs, selected) { specs.flatMap { it.requires }.filter { it.tier == selected }.distinct() }
        // A fresh list per tab, so each one opens at its top.
        key(selected) {
            LazyColumn(
                modifier = Modifier.fillMaxSize().testTag(CATALOG_LIST_TAG),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item(key = "tier") {
                    TierCard(selected, tierState(selected, grants, needed.toSet()), grants, needed, shizuku, scanning, actions)
                }
                if (specs.isEmpty()) {
                    item(key = "none") {
                        Text(
                            stringResource(R.string.catalog_none),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(4.dp),
                        )
                    }
                } else {
                    item(key = "count") { SectionHeader(stringResource(R.string.catalog_count, specs.size)) }
                }
                for (category in Category.entries) {
                    val inCategory = specs.filter { it.category == category }
                    if (inCategory.isEmpty()) continue
                    item(key = "category-${category.name}") { CategoryTitle(category) }
                    items(inCategory, key = { it.id }) { spec ->
                        CatalogCheckCard(
                            spec = spec,
                            finding = findings[spec.id],
                            muted = spec.id in muted,
                            onMute = { actions.setMuted(spec.id, it) },
                            onOpen = { onOpenCheck(spec.id) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CategoryTitle(category: Category) {
    Row(Modifier.padding(start = 4.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        IconBadge(category.icon, category.accent, size = 28.dp)
        Spacer(Modifier.width(10.dp))
        Text(stringResource(category.labelRes), style = MaterialTheme.typography.titleSmall)
    }
}

/** A check's description that expands into what it checks, what to do, and its mute switch. */
@Composable
private fun CatalogCheckCard(
    spec: CheckSpec,
    finding: Finding?,
    muted: Boolean,
    onMute: (Boolean) -> Unit,
    onOpen: () -> Unit,
) {
    val severity = stringResource(spec.severity.labelRes)
    val subtitle = if (muted) "${spec.id} · $severity · ${stringResource(R.string.muted)}" else "${spec.id} · $severity"
    ExpandableCard(
        title = spec.title,
        subtitle = subtitle,
        leading = {
            VerdictIcon(finding?.verdict, modifier = Modifier.alpha(if (muted) MUTED_ALPHA else 1f), size = 26.dp)
        },
    ) {
        Text(spec.explanation, style = MaterialTheme.typography.bodyMedium)
        if (spec.failsWhen.isNotBlank()) {
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.catalog_fails_when, spec.failsWhen),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(
            spec.remediation.text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = muted, onValueChange = onMute, role = Role.Switch)
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.detail_mute), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            Switch(checked = muted, onCheckedChange = null)
        }
        TextButton(onClick = onOpen) {
            Text(stringResource(R.string.catalog_open_result))
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null)
        }
    }
}
