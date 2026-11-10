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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DataObject
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.ReportFormat
import io.github.capitan0n.droynis.UiState
import io.github.capitan0n.droynis.schedule.ScanInterval
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** What leaves the phone or runs later: report export and the scheduled scan. */
@Composable
fun ReportsScreen(state: UiState, actions: AppActions) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { ReportCard(reportReady = state.result != null, hidePersonal = state.hidePersonal, actions = actions) }
        item { ScheduleCard(state, actions) }
    }
}

@Composable
private fun ReportCard(reportReady: Boolean, hidePersonal: Boolean, actions: AppActions) {
    SectionCard(
        title = stringResource(R.string.tools_report),
        icon = Icons.Rounded.Description,
        accent = MaterialTheme.colorScheme.tertiary,
    ) {
        Text(stringResource(R.string.report_body), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(6.dp))
        Text(
            stringResource(R.string.report_no_ids),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(10.dp))
        // The same switch as in the ⋮ menu: shown here, so it is clear what the buttons below export.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = hidePersonal, role = Role.Switch, onValueChange = actions::setHidePersonal),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.menu_hide_personal), style = MaterialTheme.typography.bodyMedium)
                Text(
                    stringResource(if (hidePersonal) R.string.personal_hidden else R.string.personal_included),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(12.dp))
            Switch(checked = hidePersonal, onCheckedChange = null)
        }
        Spacer(Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { actions.saveReport(ReportFormat.MARKDOWN) }, enabled = reportReady) {
                Icon(Icons.Rounded.Save, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text(stringResource(R.string.report_save))
            }
            Button(onClick = { actions.saveReport(ReportFormat.JSON) }, enabled = reportReady) {
                Icon(Icons.Rounded.DataObject, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text(stringResource(R.string.report_save_json))
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton(onClick = actions::shareReport, enabled = reportReady) {
                Icon(Icons.Rounded.Share, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text(stringResource(R.string.report_share))
            }
            OutlinedButton(onClick = actions::copyReport, enabled = reportReady) {
                Text(stringResource(R.string.report_copy))
            }
        }
        if (!reportReady) {
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.report_not_ready), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun ScheduleCard(state: UiState, actions: AppActions) {
    SectionCard(
        title = stringResource(R.string.tools_schedule),
        icon = Icons.Rounded.Schedule,
    ) {
        Text(stringResource(R.string.schedule_body), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(6.dp))
        Column(Modifier.selectableGroup()) {
            for (interval in ScanInterval.entries) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = interval == state.schedule,
                            onClick = { actions.setSchedule(interval) },
                            role = Role.RadioButton,
                        )
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = interval == state.schedule, onClick = null)
                    Spacer(Modifier.width(12.dp))
                    Text(
                        stringResource(
                            when (interval) {
                                ScanInterval.OFF -> R.string.schedule_off
                                ScanInterval.DAILY -> R.string.schedule_daily
                                ScanInterval.WEEKLY -> R.string.schedule_weekly
                            },
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
        if (state.schedule == ScanInterval.OFF) return@SectionCard
        // Without this, scans that wait for the app to open look like notifications that don't work.
        val heldBack = when {
            state.backgroundRestricted -> R.string.schedule_background_restricted
            state.scheduleLate -> R.string.schedule_late
            else -> null
        }
        if (heldBack != null) {
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(heldBack),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            TextButton(onClick = actions::openBatterySettings) {
                Text(stringResource(R.string.schedule_app_info))
            }
        }
        Spacer(Modifier.height(6.dp))
        // Turning this on is the only place Droynis asks for the notification permission.
        ScheduleSwitch(
            title = stringResource(R.string.schedule_notify),
            summary = stringResource(if (state.notify) R.string.schedule_notify_on else R.string.schedule_notify_off),
            checked = state.notify,
            onChange = actions::setNotify,
        )
        if (state.notify) {
            Spacer(Modifier.height(10.dp))
            ScheduleSwitch(
                title = stringResource(R.string.schedule_verbose),
                summary = stringResource(if (state.verbose) R.string.schedule_verbose_on else R.string.schedule_verbose_off),
                checked = state.verbose,
                onChange = actions::setVerbose,
            )
            if (!state.notificationsAllowed) {
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.schedule_notifications_off),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                TextButton(onClick = actions::openNotificationSettings) {
                    Text(stringResource(R.string.schedule_notification_settings))
                }
            }
        }
        Spacer(Modifier.height(10.dp))
        val lastRun = state.lastScheduledScan
        Text(
            text = if (lastRun == null) {
                stringResource(R.string.schedule_never_ran)
            } else {
                stringResource(R.string.schedule_last_run, remember(lastRun) { formatTime(lastRun) })
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        val result = state.lastScheduledResult
        if (lastRun != null && result != null) {
            Text(result, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = actions::runScheduledScan, enabled = !state.runningScheduledScan) {
            Text(stringResource(R.string.schedule_run_now))
        }
    }
}

@Composable
private fun ScheduleSwitch(title: String, summary: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            Text(summary, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = null)
    }
}

/** e.g. "5 Nov 2026, 14:02", in the phone's language and time zone. */
private fun formatTime(epochMillis: Long): String =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
        .format(Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault()))
