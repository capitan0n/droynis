package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.core.Check

/**
 * Registry of ADB-tier checks, in display order. They run only once the user has granted what
 * [io.github.capitan0n.droynis.core.CheckSpec.requires] lists; until then they show as N/A.
 */
fun adbChecks(probes: AdbProbes): List<Check> = listOf(
    BackgroundSensorUseCheck(probes.dumpsys, probes.packages),
)
