package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.checks.shizuku.PrivilegedShell
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.platform.root.RootShell
import io.github.capitan0n.droynis.platform.shizuku.ShizukuShell

/** The fixed reads both privileged shells offer: Shizuku's shell user and root. */
interface ShellAccess {
    /** True while the shell can answer right now. */
    val isReady: Boolean

    /** `settings get` as the shell, which Android never redacts or denies. */
    fun readSetting(table: String, key: String): Reading<String?>

    fun selinuxMode(): Reading<String>

    /** `dumpsys <service>` for an allowlisted service. */
    fun dumpsys(service: String): Reading<String>
}

/**
 * Picks the shell to read through: Shizuku while connected, as it has the fewest rights, else root
 * while its shell is open.
 */
internal class ShellRouter(
    private val shizuku: ShizukuShell,
    private val root: RootShell,
) : PrivilegedShell {

    fun active(): ShellAccess? = when {
        shizuku.isReady -> shizuku
        root.isReady -> root
        else -> null
    }

    override fun selinuxMode(): Reading<String> =
        active()?.selinuxMode() ?: Reading.Unavailable("neither Shizuku nor root is connected", Source("getenforce"))
}
