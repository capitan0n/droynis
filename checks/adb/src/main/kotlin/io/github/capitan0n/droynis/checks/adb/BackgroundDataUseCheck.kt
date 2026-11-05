package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.adb.BackgroundSensorUseCheck.Companion.FOREGROUND
import io.github.capitan0n.droynis.checks.adb.BackgroundSensorUseCheck.Companion.STATE_NAMES
import io.github.capitan0n.droynis.checks.adb.BackgroundSensorUseCheck.Companion.describe
import io.github.capitan0n.droynis.checks.base.AppOrigin
import io.github.capitan0n.droynis.checks.base.DefaultAppsProbe
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.checks.base.onlyTrusted
import io.github.capitan0n.droynis.checks.base.originOf
import io.github.capitan0n.droynis.checks.base.splitTrusted
import io.github.capitan0n.droynis.checks.base.trustOf
import io.github.capitan0n.droynis.checks.base.withTrustNote
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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * User apps that read SMS, the call log or contacts, or received SMS, while the user wasn't using
 * them, from the same app-ops history as SUSP-5102. The default SMS and phone apps are left out
 * for what their role needs, unless they came from outside an app store.
 */
class BackgroundDataUseCheck(
    private val dumpsys: Dumpsys,
    private val packages: PackageInventory,
    private val defaults: DefaultAppsProbe,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5104",
        category = Category.SUSPICIOUS_APPS,
        title = "Background SMS, call log and contacts use",
        severity = Severity.NOTICE,
        explanation = "Lists apps you installed that read your SMS, call log or contacts, or received SMS, while " +
            "you weren't using them, in the last ${WINDOW.inWholeDays} days. Stalkerware sends these out in the " +
            "background; so do apps that sync messages to a computer, such as KDE Connect, so check that each one " +
            "is expected. Your default SMS and phone apps are left out for what their role needs. Android keeps this " +
            "record in its app-ops service, which only the ADB or Shizuku tier can read.",
        remediation = Remediation(
            text = "Open Settings › Apps › the app › Permissions and remove SMS, Call logs and Contacts from apps " +
                "that don't need them. Uninstall apps you don't recognize.",
            settingsActions = listOf(SettingsActions.PRIVACY, SettingsActions.APPS),
        ),
        // The "Access: [state-flags]" format exists from Android 10; older output is not parsed.
        minSdk = 29,
        requires = setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS),
        timeout = 15.seconds,
        failsWhen = "a user app read SMS, the call log or contacts, or received SMS, from the background in the last " +
            "7 days (warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = when (val reading = dumpsys.dump(BackgroundSensorUseCheck.SERVICE)) {
            is Reading.Value -> reading
            is Reading.Unsupported -> return Outcome.unsupported(
                "The app-ops service is not available (${reading.reason})",
                listOf(reading.toEvidence("App-op history")),
            )
            is Reading.Unavailable -> return Outcome.unknown(
                "App-op history could not be read (${reading.reason})",
                listOf(reading.toEvidence("App-op history")),
            )
        }
        val source = dump.source
        val parsed = when (val result = AppOpsDump.parse(dump.value)) {
            is AppOpsDump.Result.Failed -> return Outcome.unknown(
                "App-op history is in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("App-op history", null, source, note = result.reason)),
            )
            is AppOpsDump.Result.Parsed -> result
        }

        val hits = parsed.accesses.filter { it.op in OPS && it.uidState !in FOREGROUND && it.ago <= WINDOW }
        val checked = Evidence(
            "Records read",
            "${count(parsed.accesses.size, "access record")} from ${count(parsed.packages, "app")}",
            source,
        )
        if (hits.isEmpty()) return Outcome.pass(NONE, listOf(checked))

        val apps = when (val installed = packages.installedApps()) {
            is Reading.Value -> installed.value.associateBy { it.packageName }
            else -> return Outcome.unknown(
                "Some apps read personal data from the background, but the app list to tell system apps apart could not be read",
                listOf(checked, installed.toEvidence("Installed apps") { "${it.size} apps" }),
            )
        }
        val smsApp = (defaults.smsApp() as? Reading.Value)?.value
        val phoneApp = (defaults.phoneApp() as? Reading.Value)?.value

        // A role explains its data only for an app that didn't come from outside an app store:
        // an SMS stealer asks to become the default SMS app.
        fun explained(pkg: String, data: Data): Boolean {
            if (originOf(pkg, apps) == AppOrigin.SIDELOADED) return false
            return (pkg == smsApp && data in SMS_ROLE) || (pkg == phoneApp && data in PHONE_ROLE)
        }

        // Unknown packages (another user's apps, for example) count as user-installed: never hide them.
        val userHits = hits.filter { apps[it.packageName]?.isSystem != true }
            .filterNot { explained(it.packageName, OPS.getValue(it.op)) }
        if (userHits.isEmpty()) {
            return Outcome.pass("Only system apps and your SMS and phone apps did, as their role needs", listOf(checked))
        }

        val all = userHits
            .groupBy { it.packageName to OPS.getValue(it.op) }
            .map { (key, accesses) -> key to accesses.minBy { it.ago } }
            .sortedWith(compareBy({ it.first.second.ordinal }, { it.second.ago }))
        val (trusted, latest) = context.splitTrusted(all) { it.first.first }
        val evidence = listOf(checked) + all.map { (key, access) ->
            val (pkg, data) = key
            val isTrusted = trusted.any { it.first == key }
            val state = STATE_NAMES[access.uidState] ?: "in app state \"${access.uidState}\""
            Evidence(
                data.label,
                "${packages.label(pkg)} ($pkg)",
                source,
                note = withTrustNote("${PHRASES.getValue(access.op)} ${describe(access.ago)}, $state", isTrusted),
                packageName = pkg,
                trust = trustOf(counted = true, trusted = isTrusted),
            )
        }
        if (latest.isEmpty()) {
            return Outcome.pass(
                onlyTrusted("used SMS, the call log or contacts from the background", trusted.map { packages.label(it.first.first) }),
                evidence,
            )
        }
        val names = latest.map { it.first.first }.distinct()
        val kinds = latest.map { it.first.second }.distinct().sortedBy { it.ordinal }
        return Outcome.fail(
            "${count(names.size, "app")} used ${kinds.joinToString(" and ") { it.noun }} from the background: " +
                names.map { packages.label(it) }.joinNames(),
            evidence,
            escalation = Severity.WARNING.takeIf { names.any { originOf(it, apps) == AppOrigin.SIDELOADED } },
        )
    }

    internal enum class Data(val label: String, val noun: String) {
        SMS("SMS", "SMS"),
        CALL_LOG("Call log", "the call log"),
        CONTACTS("Contacts", "contacts"),
    }

    internal companion object {
        val WINDOW = BackgroundSensorUseCheck.WINDOW

        const val NONE = "No app read SMS, the call log or contacts from the background in the last 7 days"

        /** App-ops as dumpsys names them. RECEIVE_SMS is noted when an SMS is delivered to the app. */
        val OPS = mapOf(
            "READ_SMS" to Data.SMS,
            "RECEIVE_SMS" to Data.SMS,
            "READ_CALL_LOG" to Data.CALL_LOG,
            "READ_CONTACTS" to Data.CONTACTS,
        )

        /** What each op means, for the evidence: "received an SMS 3 h ago, in the background". */
        val PHRASES = mapOf(
            "READ_SMS" to "read SMS",
            "RECEIVE_SMS" to "received an SMS",
            "READ_CALL_LOG" to "read the call log",
            "READ_CONTACTS" to "read contacts",
        )

        /** The default SMS app reads messages and shows senders' names; the phone app, calls and callers. */
        val SMS_ROLE = setOf(Data.SMS, Data.CONTACTS)
        val PHONE_ROLE = setOf(Data.CALL_LOG, Data.CONTACTS)
    }
}
