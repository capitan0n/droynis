package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity

object StalkerwareCheck : Check {
    private const val INACTIVE = "Currently not running by design."

    override val spec = CheckSpec(
        id = "SUSP-5007",
        category = Category.SUSPICIOUS_APPS,
        title = "Known stalkerware and monitoring apps (inactive)",
        severity = Severity.INFO,
        explanation = "$INACTIVE Droynis no longer compares installed apps against a list of known stalkerware.",
        remediation = Remediation("No action is needed for this inactive check."),
        failsWhen = "never (inactive by design)",
    )

    override suspend fun run(context: ScanContext): Outcome = Outcome.unsupported(INACTIVE)
}
