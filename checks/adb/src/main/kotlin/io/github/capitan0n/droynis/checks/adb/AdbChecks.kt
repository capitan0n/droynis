package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.core.Check

/**
 * Registry of ADB-tier checks, in display order. They run only once the user has granted what
 * [io.github.capitan0n.droynis.core.CheckSpec.requires] lists, or Shizuku covers it; until then
 * they show as N/A.
 */
fun adbChecks(probes: AdbProbes): List<Check> = (
    listOf(
        SmartLockCheck(probes.dumpsys, probes.packages),
        BackgroundSensorUseCheck(probes.dumpsys, probes.packages),
    ) + SpecialAccessCheck.Access.entries.map { SpecialAccessCheck(it, probes.dumpsys, probes.packages) } +
        WifiMacCheck(probes.dumpsys) +
        OpenWifiCheck(probes.dumpsys, probes.policy) +
        HiddenWifiCheck(probes.dumpsys) +
        HotspotCheck(probes.dumpsys) +
        HiddenBackgroundCheck(probes.dumpsys, probes.footprints, probes.packages) +
        BackgroundDataUseCheck(probes.dumpsys, probes.packages, probes.defaultApps)
    )
    // Grouped by category like the other registries (a stable sort keeps the order within each);
    // screen capture is one of the special access switches but belongs to Suspicious apps.
    .sortedBy { it.spec.category.ordinal }
