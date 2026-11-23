package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.core.Check

/**
 * Registry of root-tier checks, in display order. They run only after the user turned the root
 * tier on and the root manager granted it; until then they show as N/A.
 */
fun rootChecks(probes: RootProbes): List<Check> = listOf(
    // Device integrity
    RootModulesCheck(probes.root),
    BootScriptsCheck(probes.root),
    TempFilesCheck(probes.root),
    // Access control
    TrustedComputersCheck(probes.root),
    MagiskPromptCheck(probes.root, probes.keyguard),
    // Apps and permissions
    RootAppsCheck(probes.root, probes.packages),
    AdbRootCheck(probes.root),
    PremiumSmsCheck(probes.root, probes.packages),
    LSPosedCheck(probes.root, probes.packages),
    // Network
    ListeningAppsCheck(probes.root, probes.packages),
    QuickShareCheck(probes.root, probes.packages),
)
