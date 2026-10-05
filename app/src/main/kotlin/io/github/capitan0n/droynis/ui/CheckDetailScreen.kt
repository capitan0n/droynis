package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Lightbulb
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.QueryStats
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.report.verdict

@Composable
fun CheckDetailScreen(
    spec: CheckSpec,
    finding: Finding?,
    onOpenSettings: (List<String>) -> Unit,
    onCopy: (label: String, text: String) -> Unit,
    muted: Boolean,
    onMute: (Boolean) -> Unit,
    /** Set when the check needs grants Droynis does not hold; opens that tier's setup. */
    onSetUpTier: (() -> Unit)? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ResultHeader(spec, finding, muted)

        if (onSetUpTier != null) {
            SectionCard(
                title = stringResource(R.string.detail_needs_tier, stringResource(spec.requiredTier.labelRes)),
                icon = Icons.Rounded.Layers,
                accent = MaterialTheme.colorScheme.tertiary,
            ) {
                Text(stringResource(R.string.detail_needs_tier_body), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(12.dp))
                FilledTonalButton(onClick = onSetUpTier) {
                    Text(stringResource(R.string.detail_set_up_tier))
                }
            }
        }

        SectionCard(title = stringResource(R.string.detail_why), icon = Icons.Rounded.Lightbulb) {
            Text(spec.explanation, style = MaterialTheme.typography.bodyLarge)
        }

        SectionCard(title = stringResource(R.string.detail_what_to_do), icon = Icons.Rounded.Build) {
            Text(spec.remediation.text, style = MaterialTheme.typography.bodyLarge)
            val command = spec.remediation.command
            if (command != null) {
                Spacer(Modifier.height(12.dp))
                CodeBox(command)
            }
            if (spec.remediation.settingsActions.isNotEmpty() || command != null) {
                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (spec.remediation.settingsActions.isNotEmpty()) {
                        Button(onClick = { onOpenSettings(spec.remediation.settingsActions) }) {
                            Icon(
                                Icons.AutoMirrored.Rounded.OpenInNew,
                                contentDescription = null,
                                modifier = Modifier.size(ButtonDefaults.IconSize),
                            )
                            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                            Text(stringResource(R.string.detail_open_settings))
                        }
                    }
                    if (command != null) {
                        OutlinedButton(onClick = { onCopy(spec.title, command) }) {
                            Text(stringResource(R.string.detail_copy_command))
                        }
                    }
                }
            }
        }

        val evidence = finding?.evidence.orEmpty()
        SectionCard(
            title = stringResource(R.string.detail_evidence),
            icon = Icons.Rounded.QueryStats,
            trailing = {
                if (evidence.isNotEmpty()) {
                    IconButton(onClick = { onCopy(spec.title, evidence.joinToString("\n") { it.asLine() }) }) {
                        Icon(Icons.Rounded.ContentCopy, stringResource(R.string.detail_copy_evidence))
                    }
                }
            },
        ) {
            if (evidence.isEmpty()) {
                Text(
                    stringResource(if (finding == null) R.string.check_pending_summary else R.string.detail_evidence_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            evidence.forEachIndexed { i, item ->
                if (i > 0) HorizontalDivider(Modifier.padding(vertical = 10.dp))
                EvidenceItem(item)
            }
        }

        SectionCard(title = stringResource(R.string.detail_mute), icon = Icons.Rounded.NotificationsOff) {
            // The whole row toggles, so its text is the switch's label for screen readers too.
            Row(
                modifier = Modifier.fillMaxWidth().toggleable(value = muted, onValueChange = onMute, role = Role.Switch),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.detail_mute_body),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(12.dp))
                Switch(checked = muted, onCheckedChange = null)
            }
        }

        SectionCard(title = stringResource(R.string.detail_technical), icon = Icons.Rounded.Tune) {
            InfoRow(stringResource(R.string.detail_id), spec.id, monospace = true)
            if (spec.failsWhen.isNotBlank()) InfoRow(stringResource(R.string.detail_fails_when), spec.failsWhen)
            InfoRow(stringResource(R.string.detail_category), stringResource(spec.category.labelRes))
            InfoRow(stringResource(R.string.detail_severity), stringResource(spec.severity.labelRes))
            if (finding != null && finding.severity != spec.severity) {
                InfoRow(stringResource(R.string.detail_result_severity), stringResource(finding.severity.labelRes))
            }
            InfoRow(
                stringResource(R.string.detail_min_android),
                stringResource(R.string.detail_min_android_value, spec.minSdk),
            )
            InfoRow(stringResource(R.string.detail_tier), stringResource(spec.requiredTier.labelRes))
            if (finding != null) {
                InfoRow(
                    stringResource(R.string.detail_duration),
                    stringResource(R.string.detail_duration_value, finding.elapsedMillis.toInt()),
                )
            }
        }
    }
}

@Composable
private fun ResultHeader(spec: CheckSpec, finding: Finding?, muted: Boolean) {
    val verdict = finding?.verdict
    val tint = verdict?.style?.color ?: MaterialTheme.colorScheme.primary
    Card(
        shape = MaterialTheme.shapes.extraLarge,
        colors = CardDefaults.cardColors(containerColor = tint.copy(alpha = 0.14f)),
    ) {
        Column(Modifier.fillMaxWidth().padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                VerdictIcon(verdict, size = 44.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        stringResource(verdict?.labelRes ?: R.string.verdict_pending),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(spec.title, style = MaterialTheme.typography.headlineSmall)
                }
            }
            Spacer(Modifier.height(12.dp))
            Text(
                finding?.summary ?: stringResource(R.string.check_pending_summary),
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.height(14.dp))
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Pill(spec.id, icon = Icons.Rounded.Code)
                Pill(stringResource(spec.category.shortLabelRes), icon = spec.category.icon)
                if (finding?.status == Status.FAIL) Pill(stringResource(finding.severity.labelRes))
                if (muted) Pill(stringResource(R.string.muted), icon = Icons.Rounded.NotificationsOff)
            }
        }
    }
}

@Composable
private fun EvidenceItem(item: Evidence) {
    Column {
        Text(item.label, style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(6.dp))
        CodeBox(item.value ?: "n/a")
        if (item.note != null) {
            Spacer(Modifier.height(4.dp))
            Text(
                item.note.orEmpty(),
                style = MaterialTheme.typography.bodySmall,
                fontStyle = FontStyle.Italic,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.detail_evidence_source, item.source.toString()),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CodeBox(text: String) {
    Box(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainerHighest, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
    }
}

private fun Evidence.asLine(): String {
    val note = note?.let { " ($it)" }.orEmpty()
    return "$label: ${value ?: "n/a"}$note, via $source"
}
