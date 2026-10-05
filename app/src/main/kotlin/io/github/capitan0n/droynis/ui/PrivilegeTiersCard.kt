package io.github.capitan0n.droynis.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.RadioButtonUnchecked
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Usb
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.capitan0n.droynis.BuildConfig
import io.github.capitan0n.droynis.R
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.core.adbGrantCommand
import io.github.capitan0n.droynis.core.adbRevokeCommand
import io.github.capitan0n.droynis.ui.theme.StatusColors

/** Whether a tier works on this phone right now, can be set up, or is still to come. */
enum class TierState { ACTIVE, AVAILABLE, PLANNED }

/**
 * Base is always active; ADB is active once every grant its checks need is held; Shizuku and root
 * are planned until their checks ship.
 */
fun tierState(tier: Tier, grants: Set<Grant>, needed: Set<Grant>): TierState = when (tier) {
    Tier.BASE -> TierState.ACTIVE
    Tier.ADB -> if (needed.isNotEmpty() && grants.containsAll(needed)) TierState.ACTIVE else TierState.AVAILABLE
    Tier.SHIZUKU, Tier.ROOT -> TierState.PLANNED
}

val Tier.icon: ImageVector
    get() = when (this) {
        Tier.BASE -> Icons.Rounded.PhoneAndroid
        Tier.ADB -> Icons.Rounded.Usb
        Tier.SHIZUKU -> Icons.Rounded.Terminal
        Tier.ROOT -> Icons.Rounded.AdminPanelSettings
    }

/** The card at the top of each catalog tab: what the tier is and how to turn it on. */
@Composable
fun TierCard(
    tier: Tier,
    state: TierState,
    grants: Set<Grant>,
    needed: List<Grant>,
    scanning: Boolean,
    actions: AppActions,
) {
    SectionCard(
        title = stringResource(R.string.tier_card_title, stringResource(tier.labelRes)),
        icon = tier.icon,
        accent = if (state == TierState.ACTIVE) StatusColors.Good else MaterialTheme.colorScheme.primary,
        trailing = { TierStatePill(state) },
    ) {
        when (tier) {
            Tier.BASE -> Text(stringResource(R.string.tier_base_body), style = MaterialTheme.typography.bodyMedium)
            Tier.ADB -> AdbSetup(grants, needed, scanning, actions)
            Tier.SHIZUKU -> PlannedTier(R.string.tier_shizuku_body, R.string.tier_shizuku_steps, R.string.tier_shizuku_unlocks)
            Tier.ROOT -> PlannedTier(
                R.string.tier_root_body,
                R.string.tier_root_steps,
                R.string.tier_root_unlocks,
                note = R.string.tier_root_note,
            )
        }
    }
}

@Composable
fun TierStatePill(state: TierState) {
    Pill(
        stringResource(
            when (state) {
                TierState.ACTIVE -> R.string.tier_active
                TierState.AVAILABLE -> R.string.tier_available
                TierState.PLANNED -> R.string.tier_planned
            },
        ),
        container = if (state == TierState.ACTIVE) {
            StatusColors.Good.copy(alpha = 0.16f)
        } else {
            MaterialTheme.colorScheme.surfaceContainerHighest
        },
        content = MaterialTheme.colorScheme.onSurface,
    )
}

/**
 * Which grants are held right now, the exact adb commands for the missing ones, and the revoke
 * commands for the held ones. Only grants some check uses are listed.
 */
@Composable
private fun ColumnScope.AdbSetup(grants: Set<Grant>, needed: List<Grant>, scanning: Boolean, actions: AppActions) {
    val packageName = BuildConfig.APPLICATION_ID
    Text(stringResource(R.string.tier_adb_body), style = MaterialTheme.typography.bodyMedium)
    if (needed.isEmpty()) return

    Spacer(Modifier.height(12.dp))
    needed.forEachIndexed { i, grant ->
        if (i > 0) HorizontalDivider(Modifier.padding(vertical = 6.dp))
        GrantRow(grant, held = grant in grants)
    }

    Spacer(Modifier.height(12.dp))
    val missing = needed.filterNot { it in grants }
    val commands = missing.mapNotNull { it.adbGrantCommand(packageName) }.joinToString("\n")
    if (missing.isNotEmpty()) {
        Text(
            stringResource(R.string.tiers_adb_steps),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(10.dp))
        Surface(
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surfaceContainerHighest,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                commands,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(12.dp),
            )
        }
        Spacer(Modifier.height(10.dp))
    }
    // Stacked full width: side by side they wrap with larger fonts or longer translations.
    if (missing.isNotEmpty()) {
        Button(onClick = { actions.copy("adb", commands) }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
            Text(stringResource(R.string.tiers_copy_commands))
        }
        Spacer(Modifier.height(8.dp))
    }
    OutlinedButton(onClick = actions::scan, enabled = !scanning, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.menu_scan_again))
    }
    val held = needed.filter { it in grants }
    if (held.isNotEmpty()) {
        val revoke = held.mapNotNull { it.adbRevokeCommand(packageName) }.joinToString("\n")
        TextButton(onClick = { actions.copy("adb", revoke) }, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.tiers_copy_revoke))
        }
    }
}

/** A tier that does not exist yet: what it is, how setting it up will work, what it will add. */
@Composable
private fun ColumnScope.PlannedTier(body: Int, steps: Int, unlocks: Int, note: Int? = null) {
    Text(stringResource(body), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(12.dp))
    Text(stringResource(R.string.tier_how_it_will_work), style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(4.dp))
    Text(stringResource(steps), style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.height(12.dp))
    Text(
        stringResource(unlocks),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (note != null) {
        Spacer(Modifier.height(10.dp))
        Pill(
            text = stringResource(note),
            container = StatusColors.Critical.copy(alpha = 0.14f),
            content = MaterialTheme.colorScheme.onSurface,
            maxLines = Int.MAX_VALUE,
        )
    }
}

@Composable
private fun GrantRow(grant: Grant, held: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            if (held) Icons.Rounded.CheckCircle else Icons.Rounded.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (held) StatusColors.Good else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(grant.name, style = MaterialTheme.typography.labelLarge, fontFamily = FontFamily.Monospace)
            grant.descriptionRes?.let {
                Text(
                    stringResource(it),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Pill(
            stringResource(if (held) R.string.tiers_granted else R.string.tiers_not_granted),
            container = if (held) StatusColors.Good.copy(alpha = 0.16f) else MaterialTheme.colorScheme.surfaceContainerHighest,
            content = MaterialTheme.colorScheme.onSurface,
        )
    }
}

private val Grant.descriptionRes: Int?
    get() = when (this) {
        Grant.DUMP -> R.string.grant_dump
        Grant.PACKAGE_USAGE_STATS -> R.string.grant_usage_stats
        Grant.READ_LOGS, Grant.SHIZUKU -> null
    }
