package io.github.capitan0n.droynis.platform

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import io.github.capitan0n.droynis.checks.base.AppFootprint
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe
import io.github.capitan0n.droynis.checks.base.LauncherEntry
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * How each user app shows itself in the app drawer, and what it declares about starting on its
 * own. Needs QUERY_ALL_PACKAGES like [AndroidPackages]: without it the hiding apps would be hidden
 * from Droynis too, and the checks would pass falsely.
 *
 * Four bulk queries per scan (packages with permissions, launcher entries with and without
 * disabled ones, boot receivers), then for each user app's entries one enabled-state call and,
 * for enabled ones, one icon drawn at [AppFootprintProbe.ICON_SIZE] px.
 */
internal class AndroidAppFootprint(private val context: Context) : AppFootprintProbe {

    private val packageManager: PackageManager = context.packageManager
    private val cache = ScanCache<List<AppFootprint>>()

    override fun userApps(): Reading<List<AppFootprint>> = cache.get(::read)

    /** Drops the footprints kept for one scan. */
    fun clearCache() = cache.clear()

    private fun read(): Reading<List<AppFootprint>> {
        val source = Source("PackageManager.queryIntentActivities(MAIN, LAUNCHER)")
        return probe(source) {
            // Every launcher entry, disabled ones included, and the ones the app drawer shows now.
            val declared = launcherActivities(PackageManager.MATCH_DISABLED_COMPONENTS).groupBy { it.activityInfo.packageName }
            val shown = launcherActivities(0).mapTo(HashSet()) { it.component() }
            val atBoot = BOOT_ACTIONS.flatMapTo(HashSet()) { action -> receivers(action).map { it.activityInfo.packageName } }

            val footprints = installedPackages().mapNotNull { info ->
                val app = info.applicationInfo ?: return@mapNotNull null
                if (!isUserApp(app) || info.packageName == context.packageName) return@mapNotNull null
                val requested = info.requestedPermissions.orEmpty().toSet()
                AppFootprint(
                    packageName = info.packageName,
                    appLabel = packageManager.getApplicationLabel(app).toString(),
                    launcherEntries = declared[info.packageName].orEmpty().map { entry(it, it.component() in shown) },
                    startsAtBoot = info.packageName in atBoot && RECEIVE_BOOT_COMPLETED in requested,
                    requested = requested intersect AppFootprintProbe.WATCHED,
                )
            }
            Reading.Value(footprints, source)
        }
    }

    /** Enabled and not part of the system image; updated system apps keep FLAG_SYSTEM, like [AndroidPackages] reads it. */
    private fun isUserApp(app: ApplicationInfo): Boolean = app.enabled && (app.flags and ApplicationInfo.FLAG_SYSTEM) == 0

    private fun entry(info: ResolveInfo, enabled: Boolean): LauncherEntry {
        val component = info.component()
        val state = try {
            packageManager.getComponentEnabledSetting(component)
        } catch (e: IllegalArgumentException) {
            PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
        }
        return LauncherEntry(
            className = component.className,
            label = info.loadLabel(packageManager).toString(),
            enabled = enabled,
            turnedOff = state in TURNED_OFF,
            iconCoverage = if (enabled) iconCoverage(info) else null,
        )
    }

    /**
     * Draws the entry's icon as the app drawer would get it (an adaptive icon with its mask) and
     * returns the share of pixels more than about 10% opaque. Null when drawing fails.
     */
    private fun iconCoverage(info: ResolveInfo): Double? =
        try {
            val icon = info.loadIcon(packageManager)
            val size = AppFootprintProbe.ICON_SIZE
            val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
            try {
                icon.setBounds(0, 0, size, size)
                icon.draw(Canvas(bitmap))
                val pixels = IntArray(size * size)
                bitmap.getPixels(pixels, 0, size, 0, 0, size, size)
                pixels.count { (it ushr 24) > VISIBLE_ALPHA }.toDouble() / pixels.size
            } finally {
                bitmap.recycle()
            }
        } catch (e: Exception) {
            null
        }

    private fun ResolveInfo.component() = ComponentName(activityInfo.packageName, activityInfo.name)

    private fun launcherActivities(flags: Int): List<ResolveInfo> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))
        } else {
            legacyActivities(intent, flags)
        }
    }

    private fun receivers(action: String): List<ResolveInfo> {
        val intent = Intent(action)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryBroadcastReceivers(intent, PackageManager.ResolveInfoFlags.of(0L))
        } else {
            legacyReceivers(intent)
        }
    }

    private fun installedPackages(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            legacyInstalledPackages()
        }

    @Suppress("DEPRECATION") // the ResolveInfoFlags overload needs API 33
    private fun legacyActivities(intent: Intent, flags: Int): List<ResolveInfo> = packageManager.queryIntentActivities(intent, flags)

    @Suppress("DEPRECATION") // the ResolveInfoFlags overload needs API 33
    private fun legacyReceivers(intent: Intent): List<ResolveInfo> = packageManager.queryBroadcastReceivers(intent, 0)

    @Suppress("DEPRECATION") // the PackageInfoFlags overload needs API 33
    private fun legacyInstalledPackages(): List<PackageInfo> = packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)

    private companion object {
        const val RECEIVE_BOOT_COMPLETED = "android.permission.RECEIVE_BOOT_COMPLETED"

        /** Both start an app's receivers after a reboot; LOCKED_BOOT_COMPLETED before the first unlock. */
        val BOOT_ACTIONS = listOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_LOCKED_BOOT_COMPLETED)

        /** Set with `setComponentEnabledSetting`: by the app itself, or by a tool with its rights. */
        val TURNED_OFF = setOf(
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED,
        )

        /** Alpha above which a pixel counts as visible: about 10% opaque. */
        const val VISIBLE_ALPHA = 25
    }
}
