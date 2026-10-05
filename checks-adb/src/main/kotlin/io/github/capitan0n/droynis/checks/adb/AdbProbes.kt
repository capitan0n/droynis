package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Reading

/**
 * Runs `dumpsys` for one system service and returns what it printed. The output is unversioned,
 * OEM-specific text: checks parse it narrowly and turn anything unexpected into UNKNOWN.
 */
interface Dumpsys {
    /**
     * `Unavailable` when the service refused (for example "Permission Denial") or printed nothing,
     * `Unsupported` when the device has no such service.
     */
    fun dump(service: String, vararg args: String): Reading<String>
}

/** Everything the ADB-tier checks read. Implemented by :platform-android. */
interface AdbProbes {
    val dumpsys: Dumpsys
    val packages: PackageInventory
}
