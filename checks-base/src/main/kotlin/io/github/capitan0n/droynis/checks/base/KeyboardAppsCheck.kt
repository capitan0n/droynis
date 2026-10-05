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

class KeyboardAppsCheck(private val inputMethods: InputMethodProbe) : Check {

    override val spec = CheckSpec(
        id = "APPS-4006",
        category = Category.APPS,
        title = "Keyboard apps",
        severity = Severity.NOTICE,
        explanation = "A keyboard sees everything you type, passwords and private messages included, and " +
            "some send it to the cloud for suggestions. Keyboards built into the system come with the " +
            "phone's trust; any other one should come from a developer you trust.",
        remediation = Remediation(
            text = "Disable keyboards you do not use under Settings › System › Keyboard (the path varies). " +
                "An open-source keyboard that works offline keeps your typing on the phone.",
            settingsActions = listOf(SettingsActions.INPUT_METHODS),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val keyboards = inputMethods.enabledKeyboards()
        val evidence = keyboardEvidence(keyboards)
        return keyboards.evaluate("Enabled keyboards", evidence) { all ->
            val thirdParty = all.filterNot { it.isSystem }.map { it.app }.distinctBy { it.packageName }
            when {
                all.isEmpty() -> Outcome.unknown("The system reported no enabled keyboard", evidence)
                thirdParty.isEmpty() -> Outcome.pass(
                    "Only built-in keyboards are enabled: ${all.map { it.app.label }.distinct().joinNames()}",
                    evidence,
                )
                else -> Outcome.fail(
                    "${count(thirdParty.size, "third-party keyboard")} enabled: " +
                        thirdParty.map { it.label }.joinNames(),
                    evidence,
                )
            }
        }
    }

    private fun keyboardEvidence(keyboards: Reading<List<Keyboard>>): List<Evidence> = when (keyboards) {
        is Reading.Value -> keyboards.value.map {
            val origin = if (it.isSystem) "built-in" else "third-party"
            Evidence("Keyboard", "${it.app.label} (${it.app.packageName}), $origin", keyboards.source)
        }.ifEmpty { listOf(Evidence("Keyboard", "none", keyboards.source)) }
        else -> listOf(keyboards.toEvidence("Keyboards"))
    }
}
