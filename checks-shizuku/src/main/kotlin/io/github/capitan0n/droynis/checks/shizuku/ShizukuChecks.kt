package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.core.Check

/**
 * Registry of Shizuku-tier checks, in display order. They run only while Droynis' Shizuku shell is
 * connected; until then they show as N/A.
 */
fun shizukuChecks(probes: ShizukuProbes): List<Check> = listOf(
    // Device integrity
    SelinuxCheck(probes.shell),
    // Network
    AlwaysOnVpnCheck(probes.settings, probes.packages),
)
