package io.github.capitan0n.droynis.core

/** Privilege tiers, from least to most privileged. Detected at runtime, never assumed. */
enum class Tier { BASE, ADB, SHIZUKU, ROOT }

/**
 * A privilege a check can require on top of public APIs. A root tier adds entries here.
 *
 * @property permission the Android permission behind the grant, for `adb shell pm grant`; null when
 *   the grant is not a permission.
 */
enum class Grant(val tier: Tier, val permission: String?) {
    /**
     * The `PACKAGE_USAGE_STATS` permission itself, from `adb shell pm grant`. dumpsys services that
     * show per-app data ask for it; the Settings › Usage access switch only sets the app-op, which
     * they do not accept.
     */
    PACKAGE_USAGE_STATS(Tier.ADB, "android.permission.PACKAGE_USAGE_STATS"),

    /** `adb shell pm grant <package> android.permission.DUMP` */
    DUMP(Tier.ADB, "android.permission.DUMP"),

    /** `adb shell pm grant <package> android.permission.READ_LOGS`; Android 13+ also asks per session. */
    READ_LOGS(Tier.ADB, "android.permission.READ_LOGS"),

    /**
     * Shizuku is running, has authorized this app, and Droynis' read-only shell is connected. That
     * shell has every permission adb can grant, so it also covers the ADB-tier grants.
     */
    SHIZUKU(Tier.SHIZUKU, null),
}

/** The grants detected for this scan. */
data class Capabilities(val grants: Set<Grant> = emptySet()) {
    /** Highest tier reached by any held grant. */
    val tier: Tier get() = grants.maxOfOrNull { it.tier } ?: Tier.BASE

    /** Held directly, or covered by Shizuku: its shell has every permission adb can grant. */
    fun has(grant: Grant): Boolean = grant in grants || (grant.tier == Tier.ADB && Grant.SHIZUKU in grants)

    fun missingFor(spec: CheckSpec): Set<Grant> = spec.requires.filterNotTo(LinkedHashSet()) { has(it) }
}

/** The adb command that gives [packageName] this grant, or null when adb cannot. */
fun Grant.adbGrantCommand(packageName: String): String? =
    permission?.let { "adb shell pm grant $packageName $it" }

/** The adb command that takes this grant back. */
fun Grant.adbRevokeCommand(packageName: String): String? =
    permission?.let { "adb shell pm revoke $packageName $it" }
