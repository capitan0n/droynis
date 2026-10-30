package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Reading

/** The root manager that answers `su`. */
enum class RootManager(val label: String) {
    MAGISK("Magisk"),
    KERNELSU("KernelSU"),
    APATCH("APatch"),
    OTHER("an unknown root manager"),
}

/** Socket tables in `/proc/net`, which apps can't read since Android 10. */
enum class ProcNet(val file: String, val protocol: String) {
    TCP("tcp", "TCP"),
    TCP6("tcp6", "TCP"),
    UDP("udp", "UDP"),
    UDP6("udp6", "UDP"),
}

/**
 * Fixed, read-only reads through a root shell. Every command is a constant in the platform: no
 * method takes a path or a command, so nothing can make the shell run anything else.
 */
interface RootShellProbe {
    /** `/data/misc/adb/adb_keys`, one public key per line; `Value(null)` when the file doesn't exist. */
    fun adbKeys(): Reading<String?>

    /** Installed root modules, in the format [RootModules.parse] reads. */
    fun modules(): Reading<String>

    fun manager(): Reading<RootManager>

    /** `magisk --sqlite "SELECT uid, policy, until FROM policies"`; Magisk only. */
    fun magiskPolicies(): Reading<String>

    /** `magisk --sqlite "SELECT key, value FROM settings"`, one `key=…|value=…` per line; Magisk only. */
    fun magiskSettings(): Reading<String>

    /**
     * The boot scripts root runs under `/data/adb` and the directories that hold them, each as a
     * line `D|F <octal-perms> <owner> <path>` ([BootScripts] reads it). Covers `service.d`,
     * `post-fs-data.d` and each module's `post-fs-data.sh`/`service.sh`.
     */
    fun bootScripts(): Reading<String>

    /**
     * What is staged in `/data/local/tmp`, each entry as `D|F <octal-perms> <owner> <size> <mtime> <path>`
     * ([TempFiles] reads it).
     */
    fun tempFiles(): Reading<String>

    /** The contents of `/proc/net/<file>`; `Unsupported` when the kernel has no such table. */
    fun procNet(table: ProcNet): Reading<String>
}

/** Everything the root-tier checks read. Implemented by :platform-android. */
interface RootProbes {
    val root: RootShellProbe
    val packages: PackageInventory
}
