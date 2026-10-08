package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.util.concurrent.ConcurrentHashMap

/** Needs QUERY_ALL_PACKAGES; without it Android 11+ hides most apps and checks would pass falsely. */
internal class AndroidPackages(private val context: Context) : PackageInventory {

    private val packageManager: PackageManager = context.packageManager
    private val cache = ScanCache<List<InstalledApp>>()

    // Loading a label opens that app's resources; several checks name the same apps in one scan.
    private val labels = ConcurrentHashMap<String, String>()

    override fun installedApps(): Reading<List<InstalledApp>> = cache.get(::readApps)

    /** Drops the app list and labels kept for one scan. */
    fun clearCache() {
        cache.clear()
        labels.clear()
    }

    private fun readApps(): Reading<List<InstalledApp>> {
        val source = Source("PackageManager.getInstalledApplications()")
        return probe(source) {
            val apps = installedApplications()
                .filter { it.packageName != context.packageName }
                .map { info ->
                    val system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    InstalledApp(
                        packageName = info.packageName,
                        isSystem = system,
                        isDebuggable = (info.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                        // One binder call per app: hundreds on a phone, while only user apps' installers count.
                        installer = if (system) null else installerOf(info.packageName),
                        targetSdk = info.targetSdkVersion,
                        isEnabled = info.enabled,
                        uid = info.uid,
                    )
                }
            Reading.Value(apps, source)
        }
    }

    // computeIfAbsent: checks asking for the same label at once load it once.
    override fun label(packageName: String): String = labels.computeIfAbsent(packageName, ::loadLabel)

    private fun loadLabel(packageName: String): String =
        try {
            packageManager.getApplicationLabel(applicationInfo(packageName)).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            packageName
        }

    private fun installerOf(packageName: String): String? =
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                legacyInstaller(packageName)
            }
        } catch (e: PackageManager.NameNotFoundException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }

    @Suppress("DEPRECATION") // the replacements need API 30 / 33
    private fun legacyInstaller(packageName: String): String? = packageManager.getInstallerPackageName(packageName)

    @Suppress("DEPRECATION")
    private fun installedApplications(): List<ApplicationInfo> = packageManager.getInstalledApplications(0)

    @Suppress("DEPRECATION")
    private fun applicationInfo(packageName: String): ApplicationInfo = packageManager.getApplicationInfo(packageName, 0)
}
