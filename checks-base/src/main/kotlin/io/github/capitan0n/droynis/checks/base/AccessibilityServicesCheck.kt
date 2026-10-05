package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class AccessibilityServicesCheck(private val accessibility: AccessibilityProbe) : Check {

    override val spec = CheckSpec(
        id = "APPS-4001",
        category = Category.APPS,
        title = "Accessibility services",
        severity = Severity.NOTICE,
        explanation = "An accessibility service can read everything on screen and tap on your behalf. " +
            "Screen readers and password managers need this, but it is also the favorite tool of " +
            "Android banking trojans.",
        remediation = Remediation(
            text = "Keep only services you recognize and still use; turn the others off under " +
                "Settings › Accessibility.",
            settingsActions = listOf(SettingsActions.ACCESSIBILITY),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val services = accessibility.enabledServices()
        val evidence = appEvidence("Enabled services", services)
        return services.evaluate("Accessibility services", evidence) { apps ->
            if (apps.isEmpty()) {
                Outcome.pass("No accessibility services are enabled", evidence)
            } else {
                Outcome.fail(
                    "${count(apps.size, "accessibility service")} enabled: ${apps.map { it.label }.joinNames()}",
                    evidence,
                )
            }
        }
    }
}

/** One evidence line per app (label and package), or the reading's failure. */
internal fun appEvidence(label: String, apps: Reading<List<AppRef>>): List<Evidence> = when (apps) {
    is Reading.Value ->
        if (apps.value.isEmpty()) {
            listOf(Evidence(label, "none", apps.source))
        } else {
            apps.value.map { Evidence(label, "${it.label} (${it.packageName})", apps.source) }
        }
    else -> listOf(apps.toEvidence(label))
}
