package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.background
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
import androidx.compose.material.icons.automirrored.rounded.ListAlt
import androidx.compose.material.icons.automirrored.rounded.LiveHelp
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Insights
import androidx.compose.material.icons.rounded.PrivacyTip
import androidx.compose.material.icons.rounded.TipsAndUpdates
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.report.Grade
import io.github.capitan0n.droynis.report.HardeningIndex
import io.github.capitan0n.droynis.ui.theme.StatusColors

@Composable
fun HelpScreen(checkCount: Int, appVersion: String, onAbout: () -> Unit, onCatalog: () -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
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
        item {
            SectionCard(title = stringResource(R.string.help_legend), icon = Icons.Rounded.TipsAndUpdates) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    for (verdict in VerdictDisplayOrder) LegendRow(verdict)
                }
            }
        }
        item { ScoreCard() }
        item { PrivacyCard() }

        item { SectionHeader(stringResource(R.string.help_faq)) }
        items(FAQ) { (question, answer) ->
            ExpandableCard(
                title = stringResource(question),
                leading = {
                    Icon(Icons.AutoMirrored.Rounded.LiveHelp, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                },
            ) {
                Text(stringResource(answer), style = MaterialTheme.typography.bodyMedium)
            }
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
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(subtitle, style = MaterialTheme.typography.bodySmall)
            }
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null)
        }
    }
}

private val FAQ = listOf(
    R.string.faq_q1 to R.string.faq_a1,
    R.string.faq_q2 to R.string.faq_a2,
    R.string.faq_q3 to R.string.faq_a3,
    R.string.faq_q4 to R.string.faq_a4,
    R.string.faq_q5 to R.string.faq_a5,
    R.string.faq_q6 to R.string.faq_a6,
    R.string.faq_q8 to R.string.faq_a8,
    R.string.faq_q9 to R.string.faq_a9,
    R.string.faq_q7 to R.string.faq_a7,
)

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

@Composable
private fun PrivacyCard() {
    SectionCard(
        title = stringResource(R.string.help_privacy),
        icon = Icons.Rounded.PrivacyTip,
        accent = StatusColors.Good,
    ) {
        for (line in listOf(R.string.help_privacy_1, R.string.help_privacy_2, R.string.help_privacy_3, R.string.help_privacy_4)) {
            Row(Modifier.padding(vertical = 5.dp)) {
                Icon(
                    Icons.Rounded.CheckCircle,
                    contentDescription = null,
                    tint = StatusColors.Good,
                    modifier = Modifier.padding(top = 2.dp).size(18.dp),
                )
                Spacer(Modifier.width(10.dp))
                Text(stringResource(line), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
