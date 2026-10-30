package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.CellularProbe
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.SystemProperties
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Reading

/**
 * Read-only commands run as the shell user through Shizuku. Each one is a fixed command: the
 * platform offers no way to run anything else.
 */
interface PrivilegedShell {
    /** What `getenforce` printed: "Enforcing", "Permissive" or "Disabled". */
    fun selinuxMode(): Reading<String>

    /**
     * The kernel command line (`/proc/cmdline`): the boot parameters the bootloader passed. Apps
     * can't read it, and a boot-time property spoofer such as Magisk's `resetprop` can't change it,
     * so it is the ground truth for the `ro.boot.*` properties. `Unsupported` where the kernel
     * exposes no command line.
     */
    fun kernelCmdline(): Reading<String>
}

/**
 * Everything the Shizuku-tier checks read. Implemented by :platform-android, whose [settings]
 * fall back to the Shizuku shell for keys Android hides from apps, and whose [cellular] reads SIMs
 * as the shell user or root.
 */
interface ShizukuProbes {
    val settings: SystemSettings
    val packages: PackageInventory
    val shell: PrivilegedShell
    val cellular: CellularProbe

    /** `getprop`, an ordinary app read: the possibly-faked side that [BootPropertiesCheck] compares with the kernel. */
    val properties: SystemProperties
}
