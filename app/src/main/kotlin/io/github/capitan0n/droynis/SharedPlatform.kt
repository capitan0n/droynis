package io.github.capitan0n.droynis

import android.content.Context
import io.github.capitan0n.droynis.checks.adb.adbChecks
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.checks.root.rootChecks
import io.github.capitan0n.droynis.checks.shizuku.shizukuChecks
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.platform.AndroidPlatform
import kotlinx.coroutines.sync.Mutex

/**
 * One [AndroidPlatform] per process, shared by the screens and scheduled scans, so Droynis never
 * runs two Shizuku or root shells side by side. The first user creates it; when the last one lets
 * go, it is closed, which stops its shells.
 */
object SharedPlatform {
    private var platform: AndroidPlatform? = null
    private var users = 0

    /**
     * Held by a scan from [AndroidPlatform.newScanContext] to [AndroidPlatform.scanFinished]:
     * scanFinished closes the root shell and drops caches, which must not happen under another scan.
     */
    val scanLock = Mutex()

    @Synchronized
    fun acquire(context: Context): AndroidPlatform {
        users++
        return platform ?: AndroidPlatform(context.applicationContext).also { platform = it }
    }

    @Synchronized
    fun release(released: AndroidPlatform) {
        if (released !== platform || users == 0) return
        users--
        if (users == 0) {
            platform = null
            released.close()
        }
    }
}

/** Every check of every tier, in display order; checks above the detected tier show as N/A. */
fun allChecks(platform: AndroidPlatform): List<Check> =
    baseChecks(platform) + adbChecks(platform) + shizukuChecks(platform) + rootChecks(platform)
