package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.rounded.ListAlt
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Insights
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.TipsAndUpdates
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.report.Grade
import io.github.capitan0n.droynis.report.HardeningIndex
import io.github.capitan0n.droynis.ui.theme.StatusColors

@Composable
fun HelpScreen(
    checkCount: Int,
    appVersion: String,
    onAbout: () -> Unit,
    onCatalog: () -> Unit,
    onMutedChecks: () -> Unit,
    onTrustedApps: () -> Unit,
    onAppIcon: () -> Unit,
    onTheme: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(HELP_LIST_TAG),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "about") { AboutLink(appVersion, onAbout) }
        item(key = "catalog") {
            LinkCard(
                icon = Icons.AutoMirrored.Rounded.ListAlt,
                title = stringResource(R.string.catalog_title),
                subtitle = stringResource(R.string.help_catalog_link, checkCount),
                onClick = onCatalog,
            )
        }
        item(key = "shortcuts") {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.surfaceContainerLow,
            ) {
                Column(Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        HelpShortcut(
                            label = stringResource(R.string.help_muted_checks),
                            icon = Icons.Rounded.NotificationsOff,
                            onClick = onMutedChecks,
                            modifier = Modifier.weight(1f).fillMaxHeight(),
                        )
                        HelpShortcut(
                            label = stringResource(R.string.trusted_title),
                            icon = Icons.Rounded.VerifiedUser,
                            onClick = onTrustedApps,
                            modifier = Modifier.weight(1f).fillMaxHeight(),
                        )
                    }
                    Row(Modifier.height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        HelpShortcut(
                            label = stringResource(R.string.menu_app_icon),
                            icon = Icons.Rounded.Apps,
                            onClick = onAppIcon,
                            modifier = Modifier.weight(1f).fillMaxHeight(),
                        )
                        HelpShortcut(
                            label = stringResource(R.string.menu_theme),
                            icon = Icons.Rounded.Palette,
                            onClick = onTheme,
                            modifier = Modifier.weight(1f).fillMaxHeight(),
                        )
                    }
                }
            }
        }
        item {
            SectionCard(title = stringResource(R.string.help_legend), icon = Icons.Rounded.TipsAndUpdates) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    for (verdict in VerdictDisplayOrder) LegendRow(verdict)
                }
            }
        }
        item { ScoreCard() }
    }
}

@Composable
private fun HelpShortcut(label: String, icon: ImageVector, onClick: () -> Unit, modifier: Modifier) {
    FilledTonalButton(
        onClick = onClick,
        modifier = modifier,
        shape = MaterialTheme.shapes.medium,
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
            Text(label, textAlign = TextAlign.Center)
        }
    }
}

/** Opens the separate About page: version, author, source code and feedback. */
@Composable
private fun AboutLink(appVersion: String, onClick: () -> Unit) {
    LinkCard(
        icon = Icons.Rounded.Info,
        title = stringResource(R.string.about_title),
        subtitle = stringResource(R.string.help_about_link, appVersion),
        onClick = onClick,
        highlighted = true,
    )
}

/** A full-width card that opens another page. */
@Composable
private fun LinkCard(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit, highlighted: Boolean = false) {
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.large,
        color = if (highlighted) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerLow,
        contentColor = if (highlighted) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = if (highlighted) 22.dp else 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                val typography = MaterialTheme.typography
                Text(title, style = if (highlighted) typography.titleLarge else typography.titleMedium)
                Text(subtitle, style = MaterialTheme.typography.bodySmall)
            }
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null)
        }
    }
}

@Composable
private fun ScoreCard() {
    SectionCard(
        title = stringResource(R.string.help_score),
        icon = Icons.Rounded.Insights,
        accent = MaterialTheme.colorScheme.tertiary,
    ) {
        Text(stringResource(R.string.help_score_body), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(14.dp))
        Text(stringResource(R.string.help_weights), style = MaterialTheme.typography.labelLarge)
        for (severity in Severity.entries.sortedDescending()) {
            InfoRow(
                stringResource(severity.labelRes),
                stringResource(R.string.help_weight_value, HardeningIndex.weight(severity)),
            )
        }
        Spacer(Modifier.height(10.dp))
        Text(stringResource(R.string.help_grades), style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(6.dp))
        val grades = Grade.entries
        grades.forEachIndexed { i, grade ->
            val upper = if (i == 0) 100 else grades[i - 1].minScore - 1
            Row(Modifier.padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(30.dp).background(grade.color, CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        grade.name,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (grade.color == StatusColors.Warning) StatusColors.OnWarning else StatusColors.OnGood,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(stringResource(grade.labelRes), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                Text(
                    stringResource(R.string.grade_range, grade.minScore, upper),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        Pill(
            text = stringResource(R.string.help_score_cap),
            container = StatusColors.Critical.copy(alpha = 0.14f),
            content = MaterialTheme.colorScheme.onSurface,
            maxLines = Int.MAX_VALUE,
        )
    }
}
