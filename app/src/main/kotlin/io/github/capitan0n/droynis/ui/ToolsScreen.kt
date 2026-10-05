package io.github.capitan0n.droynis.ui

import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.DirectionsRun
import androidx.compose.material.icons.rounded.Accessibility
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Bluetooth
import androidx.compose.material.icons.rounded.CalendarMonth
import androidx.compose.material.icons.rounded.CameraAlt
import androidx.compose.material.icons.rounded.Contacts
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.DeveloperMode
import androidx.compose.material.icons.rounded.DisplaySettings
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.InstallMobile
import androidx.compose.material.icons.rounded.Keyboard
import androidx.compose.material.icons.rounded.LocationOn
import androidx.compose.material.icons.rounded.Mic
import androidx.compose.material.icons.rounded.MonitorHeart
import androidx.compose.material.icons.rounded.MyLocation
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.Nfc
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.Phone
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.PrivacyTip
import androidx.compose.material.icons.rounded.QueryStats
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.Sms
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.DroynisViewModel
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.UiState
import io.github.capitan0n.droynis.checks.base.NetworkSnapshot
import io.github.capitan0n.droynis.checks.base.Transport
import io.github.capitan0n.droynis.checks.base.WifiSecurity
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.platform.PermissionOverview
import io.github.capitan0n.droynis.platform.PermissionUsage
import io.github.capitan0n.droynis.platform.SensitivePermission
import io.github.capitan0n.droynis.report.Verdict

@Composable
fun ToolsScreen(state: UiState, actions: AppActions) {
    // Network state changes often; re-read it whenever the tab is opened.
    LaunchedEffect(Unit) { actions.refreshTools() }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { NetworkCard(state.network, state.refreshingTools, actions::refreshTools) }
        item { PermissionsCard(state.permissions) { actions.openSettings(listOf(SettingsActions.PRIVACY)) } }
        item { ShortcutsCard(actions::openSettings) }
        item { DeviceInfoCard(state, actions::copy) }
        item { ReportCard(reportReady = state.result != null, actions = actions) }
    }
}

@Composable
private fun NetworkCard(network: Reading<NetworkSnapshot?>?, refreshing: Boolean, onRefresh: () -> Unit) {
    SectionCard(
        title = stringResource(R.string.tools_network),
        icon = Icons.Rounded.NetworkCheck,
        accent = MaterialTheme.colorScheme.tertiary,
        trailing = {
            if (refreshing) {
                CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            } else {
                IconButton(onClick = onRefresh) { Icon(Icons.Rounded.Refresh, stringResource(R.string.tools_refresh)) }
            }
        },
    ) {
        when (network) {
            null -> Unit
            is Reading.Value -> {
                val net = network.value
                if (net == null) {
                    InfoRow(stringResource(R.string.net_connection), stringResource(R.string.net_offline), verdict = Verdict.UNKNOWN)
                } else {
                    NetworkRows(net)
                }
            }
            is Reading.Unsupported -> Text(stringResource(R.string.net_unavailable, network.reason))
            is Reading.Unavailable -> Text(stringResource(R.string.net_unavailable, network.reason))
        }
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.net_local_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun NetworkRows(net: NetworkSnapshot) {
    val transports = net.transports.sortedBy { it.ordinal }.map { stringResource(it.labelRes) }
    InfoRow(stringResource(R.string.net_connection), transports.joinToString(" + "))
    InfoRow(
        stringResource(R.string.net_internet),
        stringResource(if (net.validated) R.string.net_validated else R.string.net_not_validated),
    )
    InfoRow(stringResource(R.string.net_metered), stringResource(if (net.metered) R.string.yes else R.string.no))
    InfoRow(
        stringResource(R.string.net_vpn),
        stringResource(if (net.usesVpn) R.string.net_vpn_on else R.string.net_vpn_off),
        verdict = if (net.usesVpn) Verdict.PASSED else Verdict.ATTENTION,
    )
    val dnsServer = net.privateDnsServer
    InfoRow(
        stringResource(R.string.net_private_dns),
        when {
            net.privateDnsActive == null -> stringResource(R.string.net_not_reported)
            net.privateDnsActive == true && dnsServer != null -> stringResource(R.string.net_private_dns_strict, dnsServer)
            net.privateDnsActive == true -> stringResource(R.string.net_private_dns_auto)
            else -> stringResource(R.string.net_private_dns_off)
        },
        verdict = when (net.privateDnsActive) {
            true -> Verdict.PASSED
            false -> if (net.usesVpn) Verdict.PASSED else Verdict.ATTENTION
            null -> Verdict.UNKNOWN
        },
    )
    InfoRow(
        stringResource(R.string.net_dns_servers),
        net.dnsServers.joinToString("\n").ifEmpty { stringResource(R.string.net_not_reported) },
        monospace = true,
    )
    if (Transport.WIFI in net.transports) {
        val security = net.wifiSecurity
        InfoRow(
            stringResource(R.string.net_wifi_security),
            security?.label ?: stringResource(R.string.net_not_reported),
            verdict = when (security) {
                null, WifiSecurity.UNKNOWN -> Verdict.UNKNOWN
                WifiSecurity.OPEN, WifiSecurity.WEP -> if (net.usesVpn) Verdict.ATTENTION else Verdict.CRITICAL
                else -> Verdict.PASSED
            },
        )
    }
    InfoRow(
        stringResource(R.string.net_proxy),
        net.httpProxy ?: stringResource(R.string.net_none),
        monospace = net.httpProxy != null,
        verdict = if (net.httpProxy == null) Verdict.PASSED else Verdict.ATTENTION,
    )
    InfoRow(
        stringResource(R.string.net_addresses),
        net.addresses.joinToString("\n").ifEmpty { stringResource(R.string.net_not_reported) },
        monospace = true,
    )
    net.interfaceName?.let { InfoRow(stringResource(R.string.net_interface), it, monospace = true) }
}

private val Transport.labelRes: Int
    get() = when (this) {
        Transport.WIFI -> R.string.transport_wifi
        Transport.CELLULAR -> R.string.transport_cellular
        Transport.ETHERNET -> R.string.transport_ethernet
        Transport.VPN -> R.string.transport_vpn
        Transport.BLUETOOTH -> R.string.transport_bluetooth
        Transport.OTHER -> R.string.transport_other
    }

@Composable
private fun PermissionsCard(permissions: Reading<PermissionOverview>?, onManage: () -> Unit) {
    SectionCard(
        title = stringResource(R.string.tools_permissions),
        icon = Icons.Rounded.PrivacyTip,
        accent = PermissionsAccent,
    ) {
        Text(
            stringResource(R.string.permissions_intro),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        when (permissions) {
            null -> Unit
            is Reading.Value -> {
                val overview = permissions.value
                Text(
                    stringResource(R.string.permissions_inspected, overview.appsInspected),
                    style = MaterialTheme.typography.labelMedium,
                )
                Spacer(Modifier.height(4.dp))
                val most = overview.usage.maxOfOrNull { it.apps.size }?.coerceAtLeast(1) ?: 1
                for (usage in overview.usage) PermissionRow(usage, most)
            }
            is Reading.Unsupported -> Text(stringResource(R.string.permissions_unavailable, permissions.reason))
            is Reading.Unavailable -> Text(stringResource(R.string.permissions_unavailable, permissions.reason))
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onManage) { Text(stringResource(R.string.permissions_manage)) }
    }
}

private val PermissionsAccent = Color(0xFFD55181)

@Composable
private fun PermissionRow(usage: PermissionUsage, most: Int) {
    var expanded by rememberSaveable(usage.permission.name) { mutableStateOf(false) }
    val count = usage.apps.size
    Surface(
        onClick = { expanded = !expanded },
        enabled = count > 0,
        shape = MaterialTheme.shapes.small,
        color = Color.Transparent,
    ) {
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp, horizontal = 4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    usage.permission.icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stringResource(usage.permission.labelRes),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            if (count == 0) stringResource(R.string.permissions_none) else "$count",
                            style = MaterialTheme.typography.labelLarge,
                            color = if (count == 0) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    LinearProgressIndicator(
                        progress = { count / most.toFloat() },
                        modifier = Modifier.fillMaxWidth().height(6.dp),
                        color = PermissionsAccent,
                        trackColor = PermissionsAccent.copy(alpha = 0.14f),
                        strokeCap = StrokeCap.Round,
                        gapSize = 0.dp,
                        drawStopIndicator = {},
                    )
                }
                if (count > 0) {
                    Icon(
                        Icons.Rounded.ExpandMore,
                        contentDescription = stringResource(if (expanded) R.string.cd_collapse else R.string.cd_expand),
                        modifier = Modifier.rotate(if (expanded) 180f else 0f),
                    )
                }
            }
            AnimatedVisibility(visible = expanded) {
                Text(
                    usage.apps.joinToString(", ") { it.label },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 32.dp, top = 6.dp),
                )
            }
        }
    }
}

private val SensitivePermission.labelRes: Int
    get() = when (this) {
        SensitivePermission.LOCATION -> R.string.perm_location
        SensitivePermission.BACKGROUND_LOCATION -> R.string.perm_background_location
        SensitivePermission.CAMERA -> R.string.perm_camera
        SensitivePermission.MICROPHONE -> R.string.perm_microphone
        SensitivePermission.CONTACTS -> R.string.perm_contacts
        SensitivePermission.CALENDAR -> R.string.perm_calendar
        SensitivePermission.SMS -> R.string.perm_sms
        SensitivePermission.CALL_LOG -> R.string.perm_call_log
        SensitivePermission.PHONE -> R.string.perm_phone
        SensitivePermission.NEARBY_DEVICES -> R.string.perm_nearby
        SensitivePermission.PHYSICAL_ACTIVITY -> R.string.perm_activity
        SensitivePermission.BODY_SENSORS -> R.string.perm_body_sensors
        SensitivePermission.FILES_AND_MEDIA -> R.string.perm_files
    }

private val SensitivePermission.icon: ImageVector
    get() = when (this) {
        SensitivePermission.LOCATION -> Icons.Rounded.LocationOn
        SensitivePermission.BACKGROUND_LOCATION -> Icons.Rounded.MyLocation
        SensitivePermission.CAMERA -> Icons.Rounded.CameraAlt
        SensitivePermission.MICROPHONE -> Icons.Rounded.Mic
        SensitivePermission.CONTACTS -> Icons.Rounded.Contacts
        SensitivePermission.CALENDAR -> Icons.Rounded.CalendarMonth
        SensitivePermission.SMS -> Icons.Rounded.Sms
        SensitivePermission.CALL_LOG -> Icons.Rounded.History
        SensitivePermission.PHONE -> Icons.Rounded.Phone
        SensitivePermission.NEARBY_DEVICES -> Icons.Rounded.Radar
        SensitivePermission.PHYSICAL_ACTIVITY -> Icons.AutoMirrored.Rounded.DirectionsRun
        SensitivePermission.BODY_SENSORS -> Icons.Rounded.MonitorHeart
        SensitivePermission.FILES_AND_MEDIA -> Icons.Rounded.Folder
    }

private class Shortcut(val labelRes: Int, val icon: ImageVector, val action: String)

private val SHORTCUTS = listOf(
    Shortcut(R.string.shortcut_security, Icons.Rounded.Security, SettingsActions.SECURITY),
    Shortcut(R.string.shortcut_privacy, Icons.Rounded.PrivacyTip, SettingsActions.PRIVACY),
    Shortcut(R.string.shortcut_network, Icons.Rounded.NetworkCheck, SettingsActions.NETWORK),
    Shortcut(R.string.shortcut_wifi, Icons.Rounded.Wifi, SettingsActions.WIFI),
    Shortcut(R.string.shortcut_vpn, Icons.Rounded.VpnKey, SettingsActions.VPN),
    Shortcut(R.string.shortcut_bluetooth, Icons.Rounded.Bluetooth, SettingsActions.BLUETOOTH),
    Shortcut(R.string.shortcut_nfc, Icons.Rounded.Nfc, SettingsActions.NFC),
    Shortcut(R.string.shortcut_developer, Icons.Rounded.DeveloperMode, SettingsActions.DEVELOPER_OPTIONS),
    Shortcut(R.string.shortcut_accessibility, Icons.Rounded.Accessibility, SettingsActions.ACCESSIBILITY),
    Shortcut(R.string.shortcut_notifications, Icons.Rounded.NotificationsActive, SettingsActions.NOTIFICATION_ACCESS),
    Shortcut(R.string.shortcut_keyboards, Icons.Rounded.Keyboard, SettingsActions.INPUT_METHODS),
    Shortcut(R.string.shortcut_apps, Icons.Rounded.Apps, SettingsActions.APPS),
    Shortcut(R.string.shortcut_unknown_sources, Icons.Rounded.InstallMobile, SettingsActions.UNKNOWN_APP_SOURCES),
    Shortcut(R.string.shortcut_usage, Icons.Rounded.QueryStats, SettingsActions.USAGE_ACCESS),
    Shortcut(R.string.shortcut_display, Icons.Rounded.DisplaySettings, SettingsActions.DISPLAY),
    Shortcut(R.string.shortcut_about_phone, Icons.Rounded.Smartphone, SettingsActions.DEVICE_INFO),
)

@Composable
private fun ShortcutsCard(onOpen: (List<String>) -> Unit) {
    SectionCard(
        title = stringResource(R.string.tools_shortcuts),
        icon = Icons.Rounded.Security,
        accent = MaterialTheme.colorScheme.secondary,
    ) {
        Text(
            stringResource(R.string.tools_shortcuts_intro),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            for (row in SHORTCUTS.chunked(SHORTCUT_COLUMNS)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (shortcut in row) {
                        ShortcutTile(shortcut, Modifier.weight(1f)) { onOpen(listOf(shortcut.action)) }
                    }
                    repeat(SHORTCUT_COLUMNS - row.size) { Spacer(Modifier.weight(1f)) }
                }
            }
        }
    }
}

private const val SHORTCUT_COLUMNS = 3

@Composable
private fun ShortcutTile(shortcut: Shortcut, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        modifier = modifier,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier.padding(vertical = 12.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(shortcut.icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(6.dp))
            Text(
                stringResource(shortcut.labelRes),
                style = MaterialTheme.typography.labelSmall,
                textAlign = TextAlign.Center,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun DeviceInfoCard(state: UiState, onCopy: (String, String) -> Unit) {
    val device = state.device
    SectionCard(
        title = stringResource(R.string.tools_device),
        icon = Icons.Rounded.PhoneAndroid,
        trailing = {
            if (device != null) {
                IconButton(onClick = {
                    val text = DroynisViewModel.reportFacts(device).joinToString("\n") { (k, v) -> "$k: $v" }
                    onCopy(device.model, text)
                }) {
                    Icon(Icons.Rounded.ContentCopy, stringResource(R.string.device_copy))
                }
            }
        },
    ) {
        if (device == null) return@SectionCard
        InfoRow(stringResource(R.string.device_manufacturer), device.manufacturer)
        InfoRow(stringResource(R.string.device_model), device.model)
        InfoRow(
            stringResource(R.string.device_android_version),
            stringResource(R.string.device_android, device.androidVersion, device.sdkInt),
        )
        InfoRow(stringResource(R.string.device_security_patch), device.securityPatch.ifEmpty { "?" })
        InfoRow(stringResource(R.string.device_build), device.buildId, monospace = true)
        device.kernel?.let { InfoRow(stringResource(R.string.device_kernel), it, monospace = true) }
    }
}

@Composable
private fun ReportCard(reportReady: Boolean, actions: AppActions) {
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
        Spacer(Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = actions::saveReport, enabled = reportReady) {
                Icon(Icons.Rounded.Save, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text(stringResource(R.string.report_save))
            }
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
