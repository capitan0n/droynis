package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Trust

/**
 * The apps the user trusts, each with the checks that list it in the last scan but don't count
 * it. A check opens on tap; the cross stops trusting the app everywhere.
 */
@Composable
fun TrustedAppsScreen(
    /** Package names. */
    trusted: Set<String>,
    /** App labels by package; a package without one shows its package name. */
    labels: Map<String, String>,
    /** The last results by check id, to show where each trust applies. */
    findings: Map<String, Finding>,
    catalog: List<CheckSpec>,
    onUntrust: (packageName: String) -> Unit,
    onUntrustAll: () -> Unit,
    onOpenCheck: (String) -> Unit,
) {
    var confirm by rememberSaveable { mutableStateOf(false) }
    val apps = trusted.sortedBy { (labels[it] ?: it).lowercase() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            stringResource(if (trusted.isEmpty()) R.string.trusted_empty else R.string.trusted_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 4.dp),
        )

        for (pkg in apps) {
            val label = labels[pkg] ?: pkg
            // In catalog order, like everywhere else.
            val listedIn = catalog.filter { spec ->
                findings[spec.id]?.evidence.orEmpty().any { it.packageName == pkg && it.trust == Trust.TRUSTED }
            }
            SectionCard(
                title = label,
                icon = Icons.Rounded.VerifiedUser,
                trailing = {
                    IconButton(onClick = { onUntrust(pkg) }) {
                        Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.detail_untrust_app_for, label))
                    }
                },
            ) {
                Text(
                    pkg,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(if (listedIn.isEmpty()) R.string.trusted_not_listed else R.string.trusted_listed_in),
                    style = MaterialTheme.typography.labelLarge,
                )
                listedIn.forEachIndexed { i, spec ->
                    if (i > 0) HorizontalDivider()
                    CheckLinkRow(spec, onOpen = { onOpenCheck(spec.id) })
                }
            }
        }

        if (trusted.isNotEmpty()) {
            OutlinedButton(onClick = { confirm = true }, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                Icon(Icons.Rounded.Close, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text(stringResource(R.string.untrust_all))
            }
        }
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            icon = { Icon(Icons.Rounded.VerifiedUser, contentDescription = null) },
            title = { Text(stringResource(R.string.untrust_all_title)) },
            text = { Text(stringResource(R.string.untrust_all_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    onUntrustAll()
                }) { Text(stringResource(R.string.untrust_all)) }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/** A check that lists a trusted app: tap to open it. */
@Composable
private fun CheckLinkRow(spec: CheckSpec, onOpen: () -> Unit) {
    Surface(onClick = onOpen, shape = MaterialTheme.shapes.medium, color = Color.Transparent, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(vertical = 10.dp, horizontal = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(spec.title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    spec.id,
                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
