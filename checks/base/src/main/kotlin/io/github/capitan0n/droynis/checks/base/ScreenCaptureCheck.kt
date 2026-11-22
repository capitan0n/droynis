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
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence

/**
 * Whether the screen is being recorded or shared while Droynis scans: what remote-access scams
 * need, once the victim has been talked into installing a screen-sharing app.
 *
 * Android 15 tells an app whether its own screen is in a recording ([ScreenCaptureProbe.recording]),
 * not who records it. Displays other apps made public, with the app that made each, name the likely
 * app on any version ([ScreenCaptureProbe.extraDisplays]); private ones, the default for screen
 * recorders, stay hidden.
 */
class ScreenCaptureCheck(
    private val screen: ScreenCaptureProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5010",
        category = Category.SUSPICIOUS_APPS,
        title = "Screen being recorded or shared",
        severity = Severity.WARNING,
        explanation = "An app that records or shares the screen sees everything on it: messages, one-time codes " +
            "and banking apps. Scammers posing as a bank or support line talk people into installing such an app, " +
            "then watch or control the phone. Android 15 and later tell Droynis whether its own screen is being " +
            "recorded or shared; on any version, Droynis also lists displays apps made for casting or remote " +
            "control. A recording an app keeps private stays hidden before Android 15.",
        remediation = Remediation(
            text = "If you didn't start this, stop it now: open the notification shade and tap Stop on the screen " +
                "recording or casting notice, or the coloured chip in the status bar. Then uninstall the app named, " +
                "and if someone on the phone asked you to install it, hang up.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        failsWhen = "the screen is being recorded or shared while Droynis scans (Android 15+), or an app you " +
            "installed shows the screen on a display of its own (critical when that app came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val recording = screen.recording()
        val displays = screen.extraDisplays()
        val inventory = packages.byPackage()

        // Apps that made a display, unless they came with the phone; physical screens aren't counted.
        val shown = (displays as? Reading.Value)?.value.orEmpty()
        val owners = shown.mapNotNull { it.ownerPackage }
            .filter { it != context.appPackage && inventory?.get(it)?.isSystem != true }
            .distinct()
            .map { Holder(AppRef(it, packages.label(it)), originOf(it, inventory)) }
        val (trusted, counted) = context.splitTrusted(owners) { it.app.packageName }
        val recorded = (recording as? Reading.Value)?.value == ScreenRecording.RECORDED
        // With Android's own answer at hand, a display counts only while the screen is in fact recorded.
        val ownersCount = recording !is Reading.Value || recorded

        val evidence = buildList {
            add(recording.toEvidence("Screen recorded or shared right now") { if (it == ScreenRecording.RECORDED) "yes" else "no" })
            add(displays.toEvidence("Other displays") { it.size.toString() })
            shown.forEach { display -> add(displayEvidence(display, owners, trusted, ownersCount, displays.source)) }
        }

        if (recorded) {
            val by = if (counted.isEmpty()) "" else ", likely by ${counted.labels().joinNames()}"
            return Outcome.fail(
                "The screen is being recorded or shared right now$by",
                evidence,
                escalation = Severity.CRITICAL.takeIf { counted.any { it.origin == AppOrigin.SIDELOADED } },
            )
        }
        if (recording is Reading.Value) {
            return Outcome.pass("Nothing records or shares the screen right now", evidence)
        }
        if (counted.isNotEmpty()) {
            return Outcome.fail(
                "${counted.labels().joinNames()} ${if (counted.size == 1) "shows" else "show"} the screen on a display of " +
                    "${if (counted.size == 1) "its" else "their"} own, which can mirror or record it",
                evidence,
                escalation = Severity.CRITICAL.takeIf { counted.any { it.origin == AppOrigin.SIDELOADED } },
            )
        }
        if (trusted.isNotEmpty()) {
            return Outcome.pass(onlyTrusted("show the screen on a display of their own", trusted.labels()), evidence)
        }
        if (recording is Reading.Unsupported && displays is Reading.Value) {
            return Outcome.unsupported(
                "No app shows the screen on a display Droynis can see; Android before 15 doesn't tell apps about the rest",
                evidence,
            )
        }
        val reason = (recording as? Reading.Unavailable)?.reason ?: (displays as? Reading.Unavailable)?.reason ?: "not readable"
        return Outcome.unknown("Could not tell whether the screen is recorded ($reason)", evidence)
    }

    private fun displayEvidence(
        display: ExtraDisplay,
        owners: List<Holder>,
        trusted: List<Holder>,
        ownersCount: Boolean,
        source: Source,
    ): Evidence {
        val name = display.name.ifBlank { "unnamed" }
        val owner = owners.firstOrNull { it.app.packageName == display.ownerPackage }
            ?: return Evidence(
                "Display ${display.displayId}",
                name,
                source,
                note = when (display.ownerPackage) {
                    null -> "a physical screen, or Android doesn't say which app made it"
                    else -> "made by ${display.ownerPackage}, part of the system; not counted"
                },
            )
        val isTrusted = owner in trusted
        val kind = if (display.presentation) "for the app's own content" else "can mirror the screen"
        return Evidence(
            "Display ${display.displayId}",
            "$name, made by ${owner.app.label} (${owner.app.packageName})",
            source,
            note = withTrustNote(
                "$kind; ${owner.origin.note}" + if (!ownersCount && !isTrusted) "; not counted: the screen isn't recorded" else "",
                isTrusted,
            ),
            packageName = owner.app.packageName,
            trust = trustOf(counted = ownersCount, trusted = isTrusted),
        )
    }
}
