package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Telephony
import android.telecom.TelecomManager
import io.github.capitan0n.droynis.checks.base.DefaultAppsProbe
import io.github.capitan0n.droynis.checks.base.PermissionProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** Which apps hold a permission right now. Needs QUERY_ALL_PACKAGES to see every app. */
internal class AndroidPermissions(private val context: Context) : PermissionProbe {

    override fun holders(permissions: Set<String>): Reading<Map<String, Set<String>>> {
        val source = Source("PackageManager.getInstalledPackages(GET_PERMISSIONS)")
        return probe(source) {
            val holders = installedPackages()
                .filter { it.packageName != context.packageName }
                .associate { it.packageName to it.granted(permissions) }
                .filterValues { it.isNotEmpty() }
            Reading.Value(holders, source)
        }
    }

    private fun PackageInfo.granted(wanted: Set<String>): Set<String> {
        val requested = requestedPermissions ?: return emptySet()
        val flags = requestedPermissionsFlags ?: return emptySet()
        return requested.indices
            .filter { i -> requested[i] in wanted && i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0 }
            .mapTo(mutableSetOf()) { requested[it] }
    }

    private fun installedPackages(): List<PackageInfo> {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            legacyInstalledPackages(pm)
        }
    }

    @Suppress("DEPRECATION") // the replacement needs API 33
    private fun legacyInstalledPackages(pm: PackageManager): List<PackageInfo> = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
}

/** The SMS and phone apps the user chose; both public APIs that need no permission. */
internal class AndroidDefaultApps(private val context: Context) : DefaultAppsProbe {

    override fun smsApp(): Reading<String?> {
        val source = Source("Telephony.Sms.getDefaultSmsPackage()")
        return probe(source) { Reading.Value(Telephony.Sms.getDefaultSmsPackage(context), source) }
    }

    override fun phoneApp(): Reading<String?> {
        val source = Source("TelecomManager.getDefaultDialerPackage()")
        return probe(source) {
            Reading.Value(context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage, source)
        }
    }
}
