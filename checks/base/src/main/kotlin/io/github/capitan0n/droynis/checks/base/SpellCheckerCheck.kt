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

class SpellCheckerCheck(
    private val settings: SystemSettings,
    private val packages: PackageInventory,
    private val isAvailable: (String) -> Reading<Boolean>,
) : Check {
    override val spec = CheckSpec(
        id = "APPS-4021",
        category = Category.APPS,
        title = "Active spell checker",
        severity = Severity.INFO,
        explanation = "Android can send text to the selected spell checker for suggestions. " +
            "This displays the service that is configured and enabled for this profile.",
        remediation = Remediation(
            text = "Search Settings for Spell checker to see the selected service or turn spell checking off.",
            settingsActions = listOf(SettingsActions.LANGUAGE_AND_INPUT),
        ),
        failsWhen = "never (reports the enabled spell checker)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = settings.secure("spell_checker_enabled")
        val evidence = listOf(enabled.settingEvidence("Spell checker switch"))
        return enabled.evaluate("The spell checker switch", evidence) { value ->
            when (switchState(value)) {
                SwitchState.OFF -> Outcome.pass("Android spell checking is off", evidence)
                // AOSP treats a readable but unset switch as enabled.
                SwitchState.ON, SwitchState.UNSET -> provider(evidence)
                SwitchState.UNEXPECTED -> Outcome.unknown("Could not verify the spell checker switch", evidence)
            }
        }
    }

    private fun provider(evidence: List<Evidence>): Outcome {
        val selected = settings.secure("selected_spell_checker")
        if (selected !is Reading.Value) {
            return Outcome.unknown("Could not read the selected spell checker", evidence + selected.toEvidence("Selected spell checker"))
        }
        val component = selected.value?.takeIf { it.isNotBlank() }
            ?: return Outcome.unknown("Android did not identify an active spell checker", evidence)
        val available = isAvailable(component)
        val details = evidence + available.toEvidence("Selected service available")
        if (available !is Reading.Value || !available.value) {
            return Outcome.unknown("Could not verify the selected spell checker is available", details)
        }
        val pkg = component.substringBefore('/')
        val app = packages.byPackage()?.get(pkg)
        val label = packages.label(pkg)
        val origin = when {
            app == null -> "install source unknown"
            app.isSystem -> "built-in"
            else -> originOf(pkg, mapOf(pkg to app)).note
        }
        return Outcome.pass(
            "Spell checker: $label ($origin)",
            details + Evidence("Active spell checker", "$label ($pkg)", selected.source, note = origin, packageName = pkg),
        )
    }
}
