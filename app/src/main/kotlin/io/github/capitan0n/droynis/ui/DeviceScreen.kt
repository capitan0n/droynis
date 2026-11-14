package io.github.capitan0n.droynis.ui

import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.DirectionsRun
import androidx.compose.material.icons.rounded.CalendarMonth
import androidx.compose.material.icons.rounded.CameraAlt
import androidx.compose.material.icons.rounded.Contacts
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.LocationOn
import androidx.compose.material.icons.rounded.Mic
import androidx.compose.material.icons.rounded.MonitorHeart
import androidx.compose.material.icons.rounded.MyLocation
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.Phone
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.PrivacyTip
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Sms
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
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

/** Facts about the phone: its build, network and app permissions. */
@Composable
fun DeviceScreen(state: UiState, actions: AppActions) {
    // Network state changes often; re-read it whenever the tab is opened.
    LaunchedEffect(Unit) { actions.refreshTools() }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { DeviceInfoCard(state, actions::copy) }
        item { NetworkCard(state.network, state.refreshingTools, actions::refreshTools) }
        item { PermissionsCard(state.permissions) { actions.openSettings(listOf(SettingsActions.PRIVACY, SettingsActions.APPS)) } }
    }
}

@Composable
private fun NetworkCard(network: Reading<NetworkSnapshot?>?, refreshing: Boolean, onRefresh: () -> Unit) {
    // Hidden by default, so a screenshot of this screen doesn't give away an address. Not stored:
    // every new start of the app hides them again.
    var showAddresses by rememberSaveable { mutableStateOf(false) }
    SectionCard(
        title = stringResource(R.string.tools_network),
        icon = Icons.Rounded.NetworkCheck,
        accent = MaterialTheme.colorScheme.tertiary,
        trailing = {
            IconButton(onClick = { showAddresses = !showAddresses }) {
                Icon(
                    if (showAddresses) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                    stringResource(if (showAddresses) R.string.net_hide_addresses else R.string.net_show_addresses),
                )
            }
            if (refreshing) {
                // Same size as the button it replaces, so the eye doesn't jump.
                Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
                }
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
                    NetworkRows(net, showAddresses)
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

/** [showAddresses] false shows IP addresses, DNS servers and the proxy as dots. */
@Composable
private fun NetworkRows(net: NetworkSnapshot, showAddresses: Boolean) {
    val address = { value: String -> if (showAddresses) value else maskAddress(value) }
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
        net.dnsServers.joinToString("\n", transform = address).ifEmpty { stringResource(R.string.net_not_reported) },
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
        net.httpProxy?.let(address) ?: stringResource(R.string.net_none),
        monospace = net.httpProxy != null,
        verdict = if (net.httpProxy == null) Verdict.PASSED else Verdict.ATTENTION,
    )
    InfoRow(
        stringResource(R.string.net_addresses),
        net.addresses.joinToString("\n", transform = address).ifEmpty { stringResource(R.string.net_not_reported) },
        monospace = true,
    )
    net.interfaceName?.let { InfoRow(stringResource(R.string.net_interface), it, monospace = true) }
}

/**
 * The same shape for every address of a kind, so nothing about it shows: "•••.•••.•••.•••" for
 * IPv4, "••••:••••:••••:••••" for IPv6 (with or without a /prefix), dots for anything else.
 */
internal fun maskAddress(value: String): String {
    val host = value.substringBefore('/')
    return when {
        IPV4.matches(host) -> "•••.•••.•••.•••"
        host.count { it == ':' } >= 2 && IPV6.matches(host) -> "••••:••••:••••:••••"
        else -> "••••••••"
    }
}

private val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")

/** Hex groups and colons, maybe an IPv4 tail ("::ffff:1.2.3.4") and a zone ("fe80::1%wlan0"). */
private val IPV6 = Regex("""[0-9A-Fa-f:.]+(%\w+)?""")

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

@Composable
private fun DeviceInfoCard(state: UiState, onCopy: (String, String) -> Unit) {
    val device = state.device
    SectionCard(
        title = stringResource(R.string.tools_device),
        icon = Icons.Rounded.PhoneAndroid,
        trailing = {
            if (device != null) {
                IconButton(onClick = {
                    val text = DroynisViewModel.reportFacts(device).joinToString("\n") { "${it.label}: ${it.value}" }
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
        InfoRow(stringResource(R.string.device_build_type), "${device.buildType}, ${device.buildTags}", monospace = true)
        device.kernel?.let { InfoRow(stringResource(R.string.device_kernel), it, monospace = true) }
    }
}
