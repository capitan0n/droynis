package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import io.github.capitan0n.droynis.checks.base.AppRef
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** Runtime permissions worth knowing about, grouped the way Android's permission manager shows them. */
enum class SensitivePermission(val label: String, val permissions: Set<String>) {
    LOCATION("Location", setOf("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION")),
    BACKGROUND_LOCATION("Location in the background", setOf("ACCESS_BACKGROUND_LOCATION")),
    CAMERA("Camera", setOf("CAMERA")),
    MICROPHONE("Microphone", setOf("RECORD_AUDIO")),
    CONTACTS("Contacts", setOf("READ_CONTACTS", "WRITE_CONTACTS")),
    CALENDAR("Calendar", setOf("READ_CALENDAR", "WRITE_CALENDAR")),
    SMS("SMS", setOf("READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH")),
    CALL_LOG("Call logs", setOf("READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS")),
    PHONE(
        "Phone",
        setOf("READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "USE_SIP"),
    ),
    NEARBY_DEVICES(
        "Nearby devices",
        setOf("BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES", "UWB_RANGING"),
    ),
    PHYSICAL_ACTIVITY("Physical activity", setOf("ACTIVITY_RECOGNITION")),
    BODY_SENSORS("Body sensors", setOf("BODY_SENSORS", "BODY_SENSORS_BACKGROUND")),
    FILES_AND_MEDIA(
        "Files and media",
        setOf(
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
            "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED", "ACCESS_MEDIA_LOCATION",
        ),
    ),
    ;

    /** Fully qualified names, e.g. "android.permission.CAMERA". */
    val qualified: Set<String> = permissions.mapTo(mutableSetOf()) { "android.permission.$it" }
}

/** The apps currently granted one [permission] group. */
data class PermissionUsage(val permission: SensitivePermission, val apps: List<AppRef>)

data class PermissionOverview(
    /** Apps inspected: everything installed that is not part of the system image. */
    val appsInspected: Int,
    val usage: List<PermissionUsage>,
)

/** For the Tools screen, not a check: which installed apps hold which sensitive permissions. */
class AndroidPermissionAudit(context: Context) {

    private val packageManager: PackageManager = context.packageManager
    private val self = context.packageName

    fun overview(): Reading<PermissionOverview> {
        val source = Source("PackageManager.getInstalledPackages(GET_PERMISSIONS)")
        return probe(source) {
            val apps = installedPackages().filter { it.packageName != self && !it.isSystem() }
            val usage = SensitivePermission.entries.map { group ->
                val holders = apps.filter { it.hasGranted(group.qualified) }
                    .map { AppRef(it.packageName, it.label()) }
                    .sortedBy { it.label.lowercase() }
                PermissionUsage(group, holders)
            }
            Reading.Value(PermissionOverview(apps.size, usage), source)
        }
    }

    private fun PackageInfo.isSystem(): Boolean =
        ((applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) != 0

    private fun PackageInfo.hasGranted(names: Set<String>): Boolean {
        val requested = requestedPermissions ?: return false
        val flags = requestedPermissionsFlags ?: return false
        return requested.indices.any { i ->
            requested[i] in names && i < flags.size &&
                (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }
    }

    private fun PackageInfo.label(): String =
        applicationInfo?.loadLabel(packageManager)?.toString() ?: packageName

    private fun installedPackages(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()),
            )
        } else {
            legacyInstalledPackages()
        }

    @Suppress("DEPRECATION") // the replacement needs API 33
    private fun legacyInstalledPackages(): List<PackageInfo> =
        packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
}
