package io.github.capitan0n.droynis.platform

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import io.github.capitan0n.droynis.core.Grant

/**
 * Detects what the user granted Droynis with adb. Read again for every scan: `pm grant` and
 * `pm revoke` take effect at once, without restarting the app.
 */
internal class AndroidGrants(private val context: Context) {

    fun detect(): Set<Grant> = buildSet {
        if (held(Grant.DUMP)) add(Grant.DUMP)
        // dumpsys wants the permission itself and an app-op that is not denied (DumpUtils).
        if (held(Grant.PACKAGE_USAGE_STATS) && usageStatsOpAllowed()) add(Grant.PACKAGE_USAGE_STATS)
    }

    private fun held(grant: Grant): Boolean {
        val permission = grant.permission ?: return false
        return context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun usageStatsOpAllowed(): Boolean {
        val appOps = context.getSystemService(AppOpsManager::class.java) ?: return false
        val mode = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
            }
        } catch (e: SecurityException) {
            return false
        }
        return mode == AppOpsManager.MODE_ALLOWED || mode == AppOpsManager.MODE_DEFAULT
    }
}
