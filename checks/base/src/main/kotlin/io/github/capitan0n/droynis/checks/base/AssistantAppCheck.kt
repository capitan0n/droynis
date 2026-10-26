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

/**
 * The digital assistant, from the Settings keys Android keeps in step with the assistant role
 * (`VoiceInteractionManagerService`, Android 17): both empty when no app holds the role, else the
 * holder's voice interaction service, or its assist activity in [ASSISTANT] alone. All four keys
 * read here are hidden but `@Readable`, and none is redacted, in Android 17.
 */
class AssistantAppCheck(
    private val settings: SystemSettings,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4011",
        category = Category.APPS,
        title = "Digital assistant app",
        severity = Severity.NOTICE,
        explanation = "The digital assistant opens when you long-press the power or home button or say " +
            "its wake word. When you call it, it can read what is on the screen and take a screenshot " +
            "(\"Use text from screen\", on unless you turn it off), and a voice assistant can listen for " +
            "its wake word. One that came with the phone is part of the system; any other one should " +
            "come from a developer you trust, and one installed from outside an app store is a warning.",
        remediation = Remediation(
            text = "Open Settings › Apps › Default apps › Digital assistant app. Choose None if you don't " +
                "use an assistant, or turn off \"Use text from screen\" and \"Use screenshot\".",
            settingsActions = listOf(SettingsActions.VOICE_INPUT, SettingsActions.DEFAULT_APPS),
        ),
        failsWhen = "the digital assistant is an app you installed (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val assistant = settings.secure(ASSISTANT)
        val voice = settings.secure(VOICE_INTERACTION_SERVICE)
        val screenText = settings.secure(ASSIST_STRUCTURE_ENABLED)
        val screenshot = settings.secure(ASSIST_SCREENSHOT_ENABLED)
        val switches = listOf(
            screenText.assistSwitchEvidence("Use text from screen ($ASSIST_STRUCTURE_ENABLED)"),
            screenshot.assistSwitchEvidence("Use screenshot ($ASSIST_SCREENSHOT_ENABLED)"),
        )
        val raw = listOf(assistant.settingEvidence(ASSISTANT), voice.settingEvidence(VOICE_INTERACTION_SERVICE))
        return assistant.evaluate("The digital assistant", raw + switches) { assist ->
            val voiceValue = (voice as? Reading.Value)?.value
            val component = listOfNotNull(assist, voiceValue).map { it.trim() }.firstOrNull { it.isNotEmpty() }
            if (component == null) {
                // Android writes an empty value when no app holds the assistant role; unset says nothing.
                return@evaluate if (assist != null) {
                    Outcome.pass("No digital assistant app is set", raw)
                } else {
                    Outcome.unknown("The digital assistant setting is not set", raw + switches)
                }
            }
            val pkg = component.substringBefore('/')
            val holder = Holder(AppRef(pkg, packages.label(pkg)), originOf(pkg, packages.byPackage()))
            val source = if (assist?.trim().isNullOrEmpty()) voice.source else assistant.source
            val evidence = listOf(
                Evidence(
                    "Digital assistant",
                    "${holder.app.label} ($component)",
                    source,
                    note = holder.origin.note,
                    packageName = holder.app.packageName,
                ),
            ) + switches
            if (holder.origin == AppOrigin.PREINSTALLED) {
                return@evaluate Outcome.pass("${holder.app.label}, which came with the phone, is the digital assistant", evidence)
            }
            val readsScreen = switchState((screenText as? Reading.Value)?.value) in setOf(SwitchState.ON, SwitchState.UNSET)
            Outcome.fail(
                "${holder.app.label} is the digital assistant" +
                    (if (readsScreen) " and can read the screen when you call it" else "") +
                    sideloadedSuffix(listOf(holder)),
                evidence,
                escalation = sideloadedEscalation(listOf(holder)),
            )
        }
    }

    /** Android treats an unset switch as on (`VoiceInteractionSessionConnection`, Android 17). */
    private fun Reading<String?>.assistSwitchEvidence(label: String): Evidence {
        if (this !is Reading.Value) return settingEvidence(label)
        val shown = when (switchState(value)) {
            SwitchState.ON -> "on"
            SwitchState.OFF -> "off"
            SwitchState.UNSET -> "$NOT_SET, on by default"
            SwitchState.UNEXPECTED -> value.orEmpty()
        }
        return Evidence(label, shown, source)
    }

    companion object {
        /** `Settings.Secure.ASSISTANT`: the assist component, a voice interaction service or an activity. */
        const val ASSISTANT = "assistant"

        /** `Settings.Secure.VOICE_INTERACTION_SERVICE` */
        const val VOICE_INTERACTION_SERVICE = "voice_interaction_service"

        /** `Settings.Secure.ASSIST_STRUCTURE_ENABLED`: "Use text from screen". */
        const val ASSIST_STRUCTURE_ENABLED = "assist_structure_enabled"

        /** `Settings.Secure.ASSIST_SCREENSHOT_ENABLED`: "Use screenshot". */
        const val ASSIST_SCREENSHOT_ENABLED = "assist_screenshot_enabled"
    }
}
