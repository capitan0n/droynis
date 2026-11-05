package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.AppFootprintProbe
import io.github.capitan0n.droynis.checks.base.AppSighting
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.escalation
import io.github.capitan0n.droynis.checks.base.judge
import io.github.capitan0n.droynis.checks.base.names
import io.github.capitan0n.droynis.checks.base.readSightings
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

/**
 * What apps without a visible app drawer icon actually do, where SUSP-5002 sees only what they
 * declare: services they started that run now, and foreground services and overlays in the
 * app-ops history.
 */
class HiddenBackgroundCheck(
    private val dumpsys: Dumpsys,
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5101",
        category = Category.SUSPICIOUS_APPS,
        title = "Hidden apps running in the background",
        severity = Severity.WARNING,
        explanation = "Lists apps without a visible app drawer icon that run a service they started themselves " +
            "right now, or that started a foreground service or drew over other apps in the last " +
            "${WINDOW.inWholeDays} days. Adware keeps running this way to show ads. SUSP-5002 sees only what apps " +
            "declare; this check sees what they do. Services that Android or another app only binds to, such as a " +
            "keyboard's, are left out. Android shows running services and the app-ops history only to the ADB or " +
            "Shizuku tier.",
        remediation = Remediation(
            text = "Uninstall apps listed here that you don't recognize. Force stop in the app's App info ends it " +
                "until it starts itself again.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        // The app-ops history needs the "Access: [state-flags]" format, which exists from Android 10.
        minSdk = 29,
        requires = setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS),
        timeout = 30.seconds,
        failsWhen = "an app that hides from the app drawer, or one without an icon from outside an app store, " +
            "runs a service it started, or started a foreground service or drew over other apps in the last 7 days " +
            "(critical when it hides and came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = readSightings(footprints, packages) { return it }
        val outOfSight = apps.outOfSight
        val evidence = mutableListOf(apps.inspected())
        if (outOfSight.isEmpty()) return Outcome.pass("Every app you installed has a visible app drawer icon", evidence)

        val services = readServices(evidence)
        val history = readHistory(evidence)
        val userId = context.appUid?.let { it / PER_USER_RANGE }

        val found = outOfSight.mapNotNull { app ->
            val running = services?.value.orEmpty().filter {
                it.packageName == app.packageName && (userId == null || it.userId == userId) && (it.started || it.foreground)
            }
            val accesses = history?.value.orEmpty().filter { it.packageName == app.packageName && it.ago <= WINDOW }
            val details = buildList {
                when {
                    running.any { it.foreground } -> add("runs a foreground service now")
                    running.isNotEmpty() -> add("runs a service it started")
                }
                accesses.filter { it.op == START_FOREGROUND }.minByOrNull { it.ago }
                    ?.let { add("started a foreground service ${BackgroundSensorUseCheck.describe(it.ago)}") }
                accesses.filter { it.op == OVERLAY }.minByOrNull { it.ago }
                    ?.let { add("drew over other apps ${BackgroundSensorUseCheck.describe(it.ago)}") }
            }
            if (details.isEmpty()) return@mapNotNull null
            val source = (if (running.isNotEmpty()) services else history)?.source ?: apps.source
            Found(app, source, details.joinToString(", "))
        }.sortedByDescending { it.app.concern }
        val judged = context.judge(found.map { it.app })
        evidence += found.map { it.app.evidence("Runs in the background", it.source, it.details, judged.isTrusted(it.app)) }

        val counted = judged.counted
        if (counted.isNotEmpty()) {
            return Outcome.fail(
                "${count(counted.size, "hidden app")} running in the background: ${counted.names()}",
                evidence,
                escalation = counted.escalation(),
            )
        }
        // A pass needs both reads: either one alone could miss what the other shows.
        if (services == null || history == null) {
            val missing = listOfNotNull("running services".takeIf { services == null }, "the app-ops history".takeIf { history == null })
            return Outcome.unknown("No hidden app was seen running, but ${missing.joinToString(" and ")} could not be read", evidence)
        }
        return Outcome.pass(judged.passSummary("No hidden app runs in the background", "run in the background"), evidence)
    }

    private class Found(val app: AppSighting, val source: Source, val details: String)

    private class Parsed<T>(val value: T, val source: Source)

    /** The running services, or null with the reason added to [evidence]. */
    private fun readServices(evidence: MutableList<Evidence>): Parsed<List<RunningService>>? {
        val dump = dumpsys.dump(SERVICES_SERVICE, *SERVICES_ARGS)
        if (dump !is Reading.Value) {
            evidence += dump.toEvidence("Running services")
            return null
        }
        return when (val parsed = ServicesDump.parse(dump.value)) {
            is ServicesDump.Result.Parsed -> Parsed(parsed.services, dump.source).also {
                evidence += Evidence("Running services", count(parsed.services.size, "service"), dump.source)
            }
            is ServicesDump.Result.Failed -> {
                evidence += Evidence("Running services", null, dump.source, note = "unexpected format: ${parsed.reason}")
                null
            }
        }
    }

    /** The app-ops history, or null with the reason added to [evidence]. */
    private fun readHistory(evidence: MutableList<Evidence>): Parsed<List<OpAccess>>? {
        val dump = dumpsys.dump(BackgroundSensorUseCheck.SERVICE)
        if (dump !is Reading.Value) {
            evidence += dump.toEvidence("App-op history")
            return null
        }
        return when (val parsed = AppOpsDump.parse(dump.value)) {
            is AppOpsDump.Result.Parsed -> Parsed(parsed.accesses, dump.source).also {
                evidence += Evidence("App-op history", count(parsed.accesses.size, "access record"), dump.source)
            }
            is AppOpsDump.Result.Failed -> {
                evidence += Evidence("App-op history", null, dump.source, note = "unexpected format: ${parsed.reason}")
                null
            }
        }
    }

    internal companion object {
        const val SERVICES_SERVICE = "activity"
        val SERVICES_ARGS = arrayOf("services")
        val WINDOW = 7.days

        /** App-ops AppOpsService records when an app starts a foreground service, and when it shows an overlay window. */
        const val START_FOREGROUND = "START_FOREGROUND"
        const val OVERLAY = "SYSTEM_ALERT_WINDOW"

        /** `UserHandle.PER_USER_RANGE`: a uid is the user id times this, plus the app id. */
        const val PER_USER_RANGE = 100_000
    }
}
