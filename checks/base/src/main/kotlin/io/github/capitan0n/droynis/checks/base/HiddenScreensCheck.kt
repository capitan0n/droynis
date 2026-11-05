package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import java.time.Duration as JavaDuration
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toKotlinDuration

/**
 * Apps without a visible app drawer icon that brought a screen of their own to the front: the
 * user has no icon to open them by, so they did it themselves, as adware does to show ads.
 */
class HiddenScreensCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
    private val usage: UsageHistoryProbe,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5003",
        category = Category.SUSPICIOUS_APPS,
        title = "Hidden apps showing screens",
        severity = Severity.WARNING,
        explanation = "An app without a visible app drawer icon has no screen you open yourself, so when it shows " +
            "one anyway, it usually opened it by itself: that is how adware shows full-screen ads over other apps. " +
            "Droynis reads Android's usage history for the last ${WINDOW.inWholeDays} days and lists hidden apps that " +
            "brought a screen of their own to the front. It needs usage access: give it to Droynis in Settings › " +
            "Apps › Special app access › Usage access, or with the ADB tier.",
        remediation = Remediation(
            text = "Uninstall apps listed here unless you opened them yourself, for example a plugin's settings from " +
                "the app it belongs to. Droynis only reads the history while it scans; to stop that, turn Usage " +
                "access off for it again.",
            settingsActions = listOf(SettingsActions.APPS, SettingsActions.USAGE_ACCESS),
        ),
        timeout = 30.seconds,
        failsWhen = "an app that hides from the app drawer, or one without an icon from outside an app store, " +
            "brought its own screen to the front in the last 7 days (critical when it hides and came from outside " +
            "an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val access = usage.hasAccess()
        val accessEvidence = access.toEvidence("Usage access") { if (it) "allowed" else "off" }
        when (access) {
            is Reading.Value -> if (!access.value) {
                return Outcome.unsupported(
                    "Needs usage access: turn it on for Droynis in Settings › Apps › Special app access › Usage access",
                    listOf(accessEvidence),
                )
            }
            is Reading.Unsupported -> return Outcome.unsupported("The usage history is not available (${access.reason})", listOf(accessEvidence))
            is Reading.Unavailable -> return Outcome.unknown("Usage access could not be checked (${access.reason})", listOf(accessEvidence))
        }

        val apps = readSightings(footprints, packages) { return it }
        val outOfSight = apps.outOfSight
        val evidence = mutableListOf(apps.inspected())
        if (outOfSight.isEmpty()) return Outcome.pass("Every app you installed has a visible app drawer icon", evidence)

        val now = context.startedAt.toInstant()
        val shown = usage.screensShown(outOfSight.mapTo(HashSet()) { it.packageName }, now.minusSeconds(WINDOW.inWholeSeconds))
        evidence += shown.toEvidence("Usage history read") { "${it.size} of ${count(outOfSight.size, "hidden app")} showed screens" }
        return shown.evaluate("The usage history", evidence) { screens ->
            val found = outOfSight.filter { it.packageName in screens }.sortedByDescending { it.concern }
            val judged = context.judge(found)
            found.forEach { app ->
                val use = screens.getValue(app.packageName)
                val ago = JavaDuration.between(use.lastShown, now).toKotlinDuration().coerceAtLeast(Duration.ZERO)
                val last = if (ago < 1.hours) "within the last hour" else "${roughly(ago)} ago"
                val details = if (use.times == 1) "showed a screen once, $last" else "showed screens ${use.times} times, most recently $last"
                evidence += app.evidence("Showed a screen", shown.source, details, judged.isTrusted(app))
            }
            val counted = judged.counted
            if (counted.isEmpty()) {
                Outcome.pass(
                    judged.passSummary(
                        "No hidden app showed a screen of its own in the last ${WINDOW.inWholeDays} days",
                        "showed screens of their own",
                    ),
                    evidence,
                )
            } else {
                Outcome.fail(
                    "${count(counted.size, "hidden app")} showed screens of ${if (counted.size == 1) "its" else "their"} own: " +
                        counted.names(),
                    evidence,
                    escalation = counted.escalation(),
                )
            }
        }
    }

    internal companion object {
        val WINDOW = 7.days
    }
}
