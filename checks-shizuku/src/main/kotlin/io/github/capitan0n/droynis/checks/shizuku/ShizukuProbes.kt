package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Reading

/**
 * Read-only commands run as the shell user through Shizuku. Each one is a fixed command: the
 * platform offers no way to run anything else.
 */
interface PrivilegedShell {
    /** What `getenforce` printed: "Enforcing", "Permissive" or "Disabled". */
    fun selinuxMode(): Reading<String>
}

/**
 * Everything the Shizuku-tier checks read. Implemented by :platform-android, whose [settings]
 * fall back to the Shizuku shell for keys Android hides from apps.
 */
interface ShizukuProbes {
    val settings: SystemSettings
    val packages: PackageInventory
    val shell: PrivilegedShell
}
