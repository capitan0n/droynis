package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source

/** Where an app came from, which changes how much a powerful access in its hands should worry you. */
enum class AppOrigin(val note: String) {
    /** Part of the phone's firmware: as trusted as the system itself, and usually not removable. */
    PREINSTALLED("came with the phone"),

    /** Installed by a known app store, after that store's review. */
    STORE("from an app store"),

    /** Installed from a file or over adb, with no store's review: what most Android malware needs. */
    SIDELOADED("installed from outside an app store"),

    /** Missing from the app list (another user's app, say): counted, never escalated. */
    UNKNOWN("not in the app list"),
}

/** The apps Droynis can see, by package; null when the list can't be read. */
fun PackageInventory.byPackage(): Map<String, InstalledApp>? =
    (installedApps() as? Reading.Value)?.value?.associateBy { it.packageName }

fun originOf(packageName: String, apps: Map<String, InstalledApp>?): AppOrigin {
    val app = apps?.get(packageName) ?: return AppOrigin.UNKNOWN
    return when {
        app.isSystem -> AppOrigin.PREINSTALLED
        app.installer in UnknownSourceAppsCheck.KNOWN_STORES -> AppOrigin.STORE
        else -> AppOrigin.SIDELOADED
    }
}

/** An app that holds a powerful access, and where it came from. */
internal data class Holder(val app: AppRef, val origin: AppOrigin) {
    fun evidence(label: String, source: Source, counted: Boolean = true) = Evidence(
        label,
        "${app.label} (${app.packageName})",
        source,
        note = origin.note + if (counted) "" else "; not counted",
    )
}

internal fun holders(apps: List<AppRef>, inventory: Map<String, InstalledApp>?): List<Holder> =
    apps.map { Holder(it, originOf(it.packageName, inventory)) }

/** A sideloaded holder raises a FAIL to a warning. */
internal fun sideloadedEscalation(counted: List<Holder>): Severity? =
    Severity.WARNING.takeIf { counted.any { it.origin == AppOrigin.SIDELOADED } }

/** "; Foo came from outside an app store", or nothing. */
internal fun sideloadedSuffix(counted: List<Holder>): String {
    val sideloaded = counted.filter { it.origin == AppOrigin.SIDELOADED }.map { it.app.label }
    if (sideloaded.isEmpty()) return ""
    return "; ${sideloaded.joinNames()} ${if (sideloaded.size == 1) "comes" else "come"} from outside an app store"
}
