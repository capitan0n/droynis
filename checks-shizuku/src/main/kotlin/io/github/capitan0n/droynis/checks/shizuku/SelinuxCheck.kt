package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class SelinuxCheck(private val shell: PrivilegedShell) : Check {

    override val spec = CheckSpec(
        id = "INTG-1201",
        category = Category.DEVICE_INTEGRITY,
        title = "SELinux mode",
        severity = Severity.CRITICAL,
        explanation = "SELinux confines every app and system service to what its policy allows, so a bug " +
            "in one of them can't take over the whole phone. Production Android always enforces it; a " +
            "permissive or disabled SELinux usually means a modified kernel or ROM. Apps can't read the " +
            "mode, but the shell user Shizuku runs as can.",
        remediation = Remediation(
            text = "Settings can't turn SELinux back on. Install firmware that keeps it enforcing, such " +
                "as the manufacturer's stock firmware or a ROM whose kernel enforces SELinux.",
        ),
        requires = setOf(Grant.SHIZUKU),
        failsWhen = "SELinux is permissive or disabled",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val mode = shell.selinuxMode()
        val evidence = listOf(mode.toEvidence("getenforce"))
        return mode.evaluate("SELinux mode", evidence) { raw ->
            when (raw.trim()) {
                ENFORCING -> Outcome.pass("SELinux is enforcing", evidence)
                PERMISSIVE -> Outcome.fail("SELinux is permissive: it logs policy violations but blocks none", evidence)
                DISABLED -> Outcome.fail("SELinux is disabled", evidence)
                else -> Outcome.unknown("Unexpected SELinux mode \"${raw.trim()}\"", evidence)
            }
        }
    }

    companion object {
        const val ENFORCING = "Enforcing"
        const val PERMISSIVE = "Permissive"
        const val DISABLED = "Disabled"
    }
}
