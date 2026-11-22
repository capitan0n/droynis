package io.github.capitan0n.droynis.platform

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import io.github.capitan0n.droynis.checks.base.ScreenUse
import io.github.capitan0n.droynis.checks.base.UsageDump
import io.github.capitan0n.droynis.checks.base.UsageHistoryProbe
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.platform.root.RootShell
import java.time.Instant

/**
 * Android's usage history (`UsageStatsManager`). Read in Droynis' own process it needs usage access:
 * the switch in Settings › Usage access, or the PACKAGE_USAGE_STATS permission from adb. Without
 * either, a connected privileged shell (Shizuku or root) reads it instead, as the shell user
 * ([UsageReader]): Droynis' own access is never changed.
 */
internal class AndroidUsageHistory(
    private val context: Context,
    private val shells: ShellRouter,
) : UsageHistoryProbe {

    override fun hasAccess(): Reading<Boolean> {
        val own = ownAccess()
        if ((own as? Reading.Value)?.value == true) return own
        val shell = shells.active() ?: return own
        val grant = if (shell is RootShell) Grant.ROOT else Grant.SHIZUKU
        return Reading.Value(true, Source("Droynis' privileged shell reads the usage history", grant))
    }

    private fun ownAccess(): Reading<Boolean> {
        val source = Source("AppOpsManager GET_USAGE_STATS (Droynis)")
        return probe(source) {
            val appOps = context.getSystemService(AppOpsManager::class.java)
                ?: return@probe Reading.Unavailable("no app-ops service", source)
            val allowed = when (usageStatsMode(appOps)) {
                AppOpsManager.MODE_ALLOWED -> true
                // Left at default, UsageStatsService accepts the permission instead (pm grant).
                AppOpsManager.MODE_DEFAULT -> Grant.PACKAGE_USAGE_STATS.permission
                    ?.let { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED } == true
                else -> false
            }
            Reading.Value(allowed, source)
        }
    }

    override fun screensShown(packages: Set<String>, since: Instant): Reading<Map<String, ScreenUse>> =
        // Without access and without a shell Android answers Droynis with an empty history, as before.
        if ((ownAccess() as? Reading.Value)?.value == true || shells.active() == null) {
            ownScreens(packages, since)
        } else {
            shellScreens(packages, since)
        }

    /** Through the privileged shell: every app's count comes back, and only the apps asked about leave this method. */
    private fun shellScreens(packages: Set<String>, since: Instant): Reading<Map<String, ScreenUse>> =
        when (val read = shells.usage(since.toEpochMilli())) {
            is Reading.Value -> when (val parsed = UsageDump.parse(read.value)) {
                is UsageDump.Result.Parsed -> Reading.Value(parsed.screens.filterKeys { it in packages }, read.source)
                is UsageDump.Result.Failed -> Reading.Unavailable(parsed.reason, read.source)
            }
            is Reading.Unsupported -> read
            is Reading.Unavailable -> read
        }

    private fun ownScreens(packages: Set<String>, since: Instant): Reading<Map<String, ScreenUse>> {
        val source = Source("UsageStatsManager.queryEvents(ACTIVITY_RESUMED)")
        return probe(source) {
            val manager = context.getSystemService(UsageStatsManager::class.java)
                ?: return@probe Reading.Unavailable("no usage stats service", source)
            // Without access Android returns an empty history, not an error: callers ask hasAccess() first.
            val events = manager.queryEvents(since.toEpochMilli(), System.currentTimeMillis())
                ?: return@probe Reading.Unavailable("no usage history returned", source)
            val event = UsageEvents.Event()
            val shown = HashMap<String, ScreenUse>()
            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.eventType != ACTIVITY_RESUMED) continue
                // Only the apps asked about leave this method; the rest of the history stays here.
                val packageName = event.packageName?.takeIf { it in packages } ?: continue
                val at = Instant.ofEpochMilli(event.timeStamp)
                val before = shown[packageName]
                shown[packageName] = if (before == null) {
                    ScreenUse(packageName, 1, at)
                } else {
                    before.copy(times = before.times + 1, lastShown = maxOf(before.lastShown, at))
                }
            }
            Reading.Value(shown, source)
        }
    }

    private fun usageStatsMode(appOps: AppOpsManager): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
        } else {
            legacyMode(appOps)
        }

    @Suppress("DEPRECATION") // unsafeCheckOpNoThrow needs API 29
    private fun legacyMode(appOps: AppOpsManager): Int =
        appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)

    private companion object {
        /** `UsageEvents.Event.ACTIVITY_RESUMED` (Android 10); the same value was `MOVE_TO_FOREGROUND` before. */
        const val ACTIVITY_RESUMED = 1
    }
}
