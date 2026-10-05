package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Email
import androidx.compose.material.icons.rounded.Gavel
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Mail
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.PrivacyTip
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.AppInfo
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.ui.theme.StatusColors

/** Who made Droynis, where its source lives and how to send feedback. */
@Composable
fun AboutScreen(appVersion: String, onOpenLink: (String) -> Unit, onFeedback: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(
            shape = MaterialTheme.shapes.extraLarge,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Box(
                    Modifier
                        .size(76.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Rounded.Shield,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp),
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
                Text(
                    stringResource(R.string.about_version, appVersion),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(6.dp))
                Pill(stringResource(R.string.app_tagline))
            }
        }

        SectionCard(title = stringResource(R.string.about_what), icon = Icons.Rounded.Info) {
            Text(stringResource(R.string.about_body), style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(10.dp))
            Text(
                stringResource(R.string.about_independent),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SectionCard(title = stringResource(R.string.about_author_title), icon = Icons.Rounded.Person) {
            Text("${AppInfo.AUTHOR} – ${AppInfo.HANDLE}", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            LinkRow(
                icon = Icons.Rounded.Code,
                label = stringResource(R.string.about_source),
                value = AppInfo.REPOSITORY.removePrefix("https://"),
            ) { onOpenLink(AppInfo.REPOSITORY) }
            LinkRow(
                icon = Icons.Rounded.Email,
                label = stringResource(R.string.about_feedback),
                value = AppInfo.FEEDBACK_EMAIL,
                onClick = onFeedback,
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onFeedback) {
                    Icon(Icons.Rounded.Mail, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                    Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                    Text(stringResource(R.string.about_send_feedback))
                }
                OutlinedButton(onClick = { onOpenLink(AppInfo.REPOSITORY) }) {
                    Text(stringResource(R.string.about_open_repo))
                }
            }
        }

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

        SectionCard(title = stringResource(R.string.about_license_title), icon = Icons.Rounded.Gavel) {
            Text(stringResource(R.string.about_license), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun LinkRow(icon: ImageVector, label: String, value: String, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.medium,
        color = Color.Transparent,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(vertical = 10.dp, horizontal = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(value, style = MaterialTheme.typography.bodyLarge)
            }
            Icon(
                Icons.AutoMirrored.Rounded.OpenInNew,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}
