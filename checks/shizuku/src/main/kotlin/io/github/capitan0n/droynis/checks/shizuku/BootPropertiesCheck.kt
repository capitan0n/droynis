package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.SystemProperties
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate

/**
 * Compares the security-relevant `ro.boot.*` properties apps read against the real values the
 * bootloader passed on the kernel command line. They are set from the command line at boot and
 * always match on an untouched phone; a boot-time spoofer (Magisk's `resetprop`, a Play-Integrity
 * module) rewrites the properties to hide an unlocked bootloader, but can't touch the command line,
 * so a mismatch is a sign of exactly that.
 */
class BootPropertiesCheck(
    private val shell: PrivilegedShell,
    private val properties: SystemProperties,
) : Check {

    override val spec = CheckSpec(
        id = "INTG-1202",
        category = Category.DEVICE_INTEGRITY,
        title = "Spoofed boot properties",
        severity = Severity.WARNING,
        explanation = "Android copies the bootloader's state into ro.boot.* properties at boot: whether the " +
            "bootloader is unlocked, whether verified boot passed, and on Samsung whether the Knox warranty " +
            "fuse is blown. Modules that hide root rewrite these to look clean, which lets other apps trust a " +
            "phone whose bootloader is actually open. The kernel command line keeps the real values, and only " +
            "a shell can read it.",
        remediation = Remediation(
            text = "A mismatch means a module is faking the bootloader state. Decide whether you want that: it " +
                "is how some apps are made to trust a rooted phone. To see the true state, remove the " +
                "props-spoofing module (often a Play Integrity or \"MagiskHide props\" module) and scan again; " +
                "the real values are what the kernel command line shows here.",
        ),
        requires = setOf(Grant.SHIZUKU),
        failsWhen = "a security-relevant ro.boot.* property differs from the kernel command line (a props spoofer)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val cmdline = shell.kernelCmdline()
        val props = properties.all()
        val propMap = (props as? Reading.Value)?.value.orEmpty()

        return cmdline.evaluate("The kernel command line", evidenceFor(cmdline, props, emptyList())) { raw ->
            if (props !is Reading.Value) {
                return@evaluate Outcome.unknown("The boot properties could not be read to compare them", evidenceFor(cmdline, props, emptyList()))
            }
            val kernel = KernelCmdline.parse(raw)
            val compared = BOOT_KEYS.mapNotNull { key ->
                val onKernel = kernel["$ANDROIDBOOT$key"]?.trim()
                val onProps = propMap["$RO_BOOT$key"]?.trim()
                if (onKernel != null && onProps != null) Compared(key, onProps, onKernel) else null
            }
            val evidence = evidenceFor(cmdline, props, compared)
            val mismatches = compared.filter { !it.value.equals(it.kernel, ignoreCase = true) }
            when {
                mismatches.isNotEmpty() -> Outcome.fail(
                    "Boot state apps see is faked: ${mismatches.joinToString("; ") { "${it.label} shows ${it.value} but the kernel says ${it.kernel}" }}",
                    evidence,
                )
                compared.isNotEmpty() -> Outcome.pass("Boot properties match the kernel command line", evidence)
                // The command line was read but held none of the keys (some phones move them to /proc/bootconfig).
                else -> Outcome.unknown("The kernel command line held none of the boot keys to compare", evidence)
            }
        }
    }

    private fun evidenceFor(cmdline: Reading<String>, props: Reading<Map<String, String>>, compared: List<Compared>): List<Evidence> {
        if (compared.isEmpty()) {
            return listOf(
                Evidence("Kernel command line", (cmdline as? Reading.Value)?.let { "read" }, cmdline.source, note = readNote(cmdline)),
                Evidence("Boot properties (getprop)", (props as? Reading.Value)?.let { "read" }, props.source, note = readNote(props)),
            )
        }
        return compared.map {
            Evidence(
                FRIENDLY[it.key] ?: it.key,
                "${RO_BOOT}${it.key}=${it.value}, ${ANDROIDBOOT}${it.key}=${it.kernel}",
                cmdline.source,
                note = if (it.value.equals(it.kernel, ignoreCase = true)) null else "property faked",
            )
        }
    }

    private fun readNote(reading: Reading<*>): String? = when (reading) {
        is Reading.Value -> null
        is Reading.Unsupported -> "not supported: ${reading.reason}"
        is Reading.Unavailable -> "not readable: ${reading.reason}"
    }

    private data class Compared(val key: String, val value: String, val kernel: String) {
        val label: String get() = FRIENDLY[key] ?: key
    }

    companion object {
        private const val ANDROIDBOOT = "androidboot."
        private const val RO_BOOT = "ro.boot."

        /** The `ro.boot.<suffix>` / `androidboot.<suffix>` pairs worth comparing, by their shared suffix. */
        val BOOT_KEYS = listOf("verifiedbootstate", "flash.locked", "vbmeta.device_state", "warranty_bit")

        private val FRIENDLY = mapOf(
            "verifiedbootstate" to "Verified boot state",
            "flash.locked" to "Bootloader lock",
            "vbmeta.device_state" to "Device state",
            "warranty_bit" to "Knox warranty bit",
        )
    }
}

/** The kernel command line as a map of its `key=value` tokens (`proc(5)`). A token without `=` maps to "". */
object KernelCmdline {
    fun parse(text: String): Map<String, String> =
        text.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.associate { token ->
            val eq = token.indexOf('=')
            if (eq < 0) token to "" else token.substring(0, eq) to token.substring(eq + 1)
        }
}
