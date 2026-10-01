package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Check

/** Registry of base-tier checks. Adding a check means one class plus one line here. */
fun baseChecks(probes: BaseProbes): List<Check> = listOf(
    SecurityPatchAgeCheck(probes.build),
    LockScreenCheck(probes.keyguard),
    UsbDebuggingCheck(probes.settings),
)
