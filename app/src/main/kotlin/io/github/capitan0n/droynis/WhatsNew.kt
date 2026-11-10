package io.github.capitan0n.droynis

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager

/**
 * "What's new": this version's F-Droid changelog, built in as [BuildConfig.WHATS_NEW], shown once
 * after an update. Never on a fresh install, and not for a version without one.
 */
internal object WhatsNew {

    private const val KEY_SEEN = "whats_new_seen"

    /**
     * The notes to show now, or null. Without notes to show, records this version as seen, so a
     * fresh install never shows the notes it came with.
     */
    fun pending(context: Context, prefs: SharedPreferences): String? {
        val current = BuildConfig.VERSION_CODE
        val seen = prefs.getInt(KEY_SEEN, -1).takeIf { it >= 0 }
        if (shouldShow(BuildConfig.WHATS_NEW, current, seen, wasUpdated(context))) return BuildConfig.WHATS_NEW
        if (seen == null || seen < current) markSeen(prefs)
        return null
    }

    /** Closed: not shown again for this version. */
    fun markSeen(prefs: SharedPreferences) {
        prefs.edit().putInt(KEY_SEEN, BuildConfig.VERSION_CODE).apply()
    }

    /**
     * Whether to show the notes of version [current]. [seen] is the last version that showed or
     * skipped them; null when none did, as on a fresh install or after an update from a version
     * before this dialog, which [updated] tells apart.
     */
    fun shouldShow(notes: String, current: Int, seen: Int?, updated: Boolean): Boolean =
        notes.isNotBlank() && (if (seen == null) updated else seen < current)

    /** Installed over an earlier version, rather than fresh. */
    private fun wasUpdated(context: Context): Boolean =
        try {
            val info = context.packageManager.getPackageInfo(context.packageName, 0)
            info.lastUpdateTime > info.firstInstallTime
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
}
