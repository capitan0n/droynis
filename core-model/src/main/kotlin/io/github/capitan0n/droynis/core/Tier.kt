package io.github.capitan0n.droynis.core

/** Privilege tiers, from least to most privileged. Detected at runtime, never assumed. */
enum class Tier { BASE, ADB, SHIZUKU, ROOT }

/** A privilege a check can require on top of public APIs. A root tier adds entries here. */
enum class Grant(val tier: Tier) {
    /** Usage access. The user can grant it in Settings › Special app access; no adb needed. */
    PACKAGE_USAGE_STATS(Tier.BASE),

    /** `adb shell pm grant <package> android.permission.DUMP` */
    DUMP(Tier.ADB),

    /** `adb shell pm grant <package> android.permission.READ_LOGS`; Android 13+ also asks per session. */
    READ_LOGS(Tier.ADB),

    /** Shizuku is running and has authorized this app. */
    SHIZUKU(Tier.SHIZUKU),
}

/** The grants detected for this scan. */
data class Capabilities(val grants: Set<Grant> = emptySet()) {
    /** Highest tier reached by any held grant. */
    val tier: Tier get() = grants.maxOfOrNull { it.tier } ?: Tier.BASE

    fun missingFor(spec: CheckSpec): Set<Grant> = spec.requires - grants
}
