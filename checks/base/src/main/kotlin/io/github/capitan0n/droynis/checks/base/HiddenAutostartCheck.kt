package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.FOREGROUND_SERVICE
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.SYSTEM_ALERT_WINDOW
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe.Companion.USE_FULL_SCREEN_INTENT
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps the user can't open from the app drawer that declare ways to run or show themselves on
 * their own. What an app declares, not what it does: SUSP-5101 sees what runs.
 */
class HiddenAutostartCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
    private val battery: BatteryProbe,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5002",
        category = Category.SUSPICIOUS_APPS,
        title = "Hidden apps set up to run in the background",
        severity = Severity.WARNING,
        explanation = "An app you can't open from the app drawer has little reason to start by itself, yet adware " +
            "does: it starts with the phone, keeps a service running and pops up over other apps. Droynis lists " +
            "apps without a visible app drawer icon that declare one of these: starting when the phone starts, " +
            "foreground services, drawing over other apps, full-screen pop-ups, or skipping battery limits. " +
            "Add-ons such as plugins often have no icon of their own; from an app store they are listed, not counted.",
        remediation = Remediation(
            text = "Uninstall apps listed here that you don't recognize. For an add-on you use, check that the app " +
                "it belongs to is one you trust.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 30.seconds,
        failsWhen = "an app that hides from the app drawer, or one without an icon from outside an app store, " +
            "declares it starts at boot, runs foreground services, draws over other apps, shows full-screen " +
            "pop-ups or skips battery limits (critical when it hides and came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = readSightings(footprints, packages) { return it }
        val found = apps.outOfSight
            .map { it to traits(it.footprint) }
            .filter { (_, traits) -> traits.isNotEmpty() }
            .sortedByDescending { (app, _) -> app.concern }
        val evidence = mutableListOf(apps.inspected())

        // Only the apps found are asked about: one binder call each.
        val exemption = if (found.isEmpty()) null else battery.unrestricted(found.map { it.first.packageName })
        val exempt = (exemption as? Reading.Value)?.value.orEmpty()
        if (exemption != null && exemption !is Reading.Value) evidence += exemption.toEvidence("Battery limits")

        val judged = context.judge(found.map { it.first })
        found.forEach { (app, traits) ->
            val notes = traits.map { if (it == Trait.BATTERY && app.packageName in exempt) EXEMPT else it.note }
            evidence += app.evidence("Runs in the background", apps.source, notes.joinToString(", "), judged.isTrusted(app))
        }

        val counted = judged.counted
        if (counted.isEmpty()) {
            return Outcome.pass(
                judged.passSummary("No hidden app is set up to run in the background", "are set up to run in the background"),
                evidence,
            )
        }
        return Outcome.fail(
            "${count(counted.size, "hidden app")} set up to run in the background: ${counted.names()}",
            evidence,
            escalation = counted.escalation(),
        )
    }

    internal enum class Trait(val note: String) {
        BOOT("starts when the phone starts"),
        FOREGROUND("can run foreground services"),
        OVERLAY("asks to draw over other apps"),
        FULL_SCREEN("can show full-screen pop-ups"),
        BATTERY("asks to skip battery limits"),
    }

    internal companion object {
        /** Shown instead of [Trait.BATTERY] when Android already lets the app skip them. */
        const val EXEMPT = "skips battery limits"

        fun traits(footprint: AppFootprint): List<Trait> = buildList {
            if (footprint.startsAtBoot) add(Trait.BOOT)
            if (FOREGROUND_SERVICE in footprint.requested) add(Trait.FOREGROUND)
            if (SYSTEM_ALERT_WINDOW in footprint.requested) add(Trait.OVERLAY)
            if (USE_FULL_SCREEN_INTENT in footprint.requested) add(Trait.FULL_SCREEN)
            if (REQUEST_IGNORE_BATTERY_OPTIMIZATIONS in footprint.requested) add(Trait.BATTERY)
        }
    }
}
