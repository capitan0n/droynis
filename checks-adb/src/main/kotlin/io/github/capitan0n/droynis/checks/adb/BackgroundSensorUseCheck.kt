package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
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
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class BackgroundSensorUseCheck(
    private val dumpsys: Dumpsys,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4101",
        category = Category.APPS,
        title = "Background camera, microphone and location use",
        severity = Severity.NOTICE,
        explanation = "Lists user-installed apps that used the camera, the microphone or your location " +
            "while you were not using them, in the last ${WINDOW.inWholeDays} days. Spyware works this way; " +
            "so do fitness, navigation and smart-home apps, so check that each one is expected. " +
            "Android keeps this record in its app-ops service, which needs the ADB tier to read.",
        remediation = Remediation(
            text = "For each app listed, open Settings › Apps › the app › Permissions. Set Location to " +
                "\"Allow only while using the app\" or \"Don't allow\", and remove Camera and Microphone " +
                "from apps that don't need them. Uninstall apps you don't recognize.",
            settingsActions = listOf(SettingsActions.PRIVACY, SettingsActions.APPS),
        ),
        // The "Access: [state-flags]" format exists from Android 10; older output is not parsed.
        minSdk = 29,
        requires = setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS),
        timeout = 15.seconds,
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = when (val reading = dumpsys.dump(SERVICE)) {
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

        val hits = parsed.accesses.filter { it.op in SENSORS && it.uidState !in FOREGROUND && it.ago <= WINDOW }
        val checked = Evidence(
            "Records read",
            "${count(parsed.accesses.size, "access record")} from ${count(parsed.packages, "app")}",
            source,
        )
        if (hits.isEmpty()) {
            return Outcome.pass(
                "No app used the camera, microphone or location from the background in the last ${WINDOW.inWholeDays} days",
                listOf(checked),
            )
        }

        // Only now are system apps worth telling apart; without the app list that is impossible.
        val apps = when (val installed = packages.installedApps()) {
            is Reading.Value -> installed.value.associateBy { it.packageName }
            else -> return Outcome.unknown(
                "Some apps used sensors from the background, but the app list to tell system apps apart could not be read",
                listOf(checked, installed.toEvidence("Installed apps") { "${it.size} apps" }),
            )
        }
        // Unknown packages (another user's apps, for example) count as user-installed: never hide them.
        val userHits = hits.filter { apps[it.packageName]?.isSystem != true }
        if (userHits.isEmpty()) {
            return Outcome.pass(
                "Only system apps used the camera, microphone or location from the background " +
                    "in the last ${WINDOW.inWholeDays} days",
                listOf(checked),
            )
        }

        val latest = userHits
            .groupBy { it.packageName to SENSORS.getValue(it.op) }
            .map { (key, accesses) -> key to accesses.minBy { it.ago } }
            .sortedWith(compareBy({ it.first.second.ordinal }, { it.second.ago }))
        val evidence = listOf(checked) + latest.map { (key, access) ->
            val (pkg, sensor) = key
            Evidence(
                sensor.label,
                "${packages.label(pkg)} ($pkg)",
                source,
                note = "last used ${describe(access.ago)}, ${STATE_NAMES[access.uidState] ?: "in app state \"${access.uidState}\""}",
            )
        }
        val names = latest.map { packages.label(it.first.first) }.distinct()
        val sensors = latest.map { it.first.second }.distinct().sortedBy { it.ordinal }
        return Outcome.fail(
            "${count(names.size, "app")} used ${sensors.joinToString(" and ") { it.noun }} from the background: " +
                names.joinNames(),
            evidence,
            escalation = Severity.WARNING.takeIf { sensors.any { it != Sensor.LOCATION } },
        )
    }

    internal enum class Sensor(val label: String, val noun: String) {
        CAMERA("Camera", "the camera"),
        MICROPHONE("Microphone", "the microphone"),
        LOCATION("Location", "location"),
    }

    internal companion object {
        const val SERVICE = "appops"
        val WINDOW = 7.days

        val SENSORS = mapOf(
            "CAMERA" to Sensor.CAMERA,
            "RECORD_AUDIO" to Sensor.MICROPHONE,
            "FINE_LOCATION" to Sensor.LOCATION,
            "COARSE_LOCATION" to Sensor.LOCATION,
        )

        /**
         * Uid states in which the user sees the app: on screen, or running a foreground service with
         * its notification (and, from Android 12, the camera or microphone indicator). Anything
         * else, including states added later, counts as background.
         */
        val FOREGROUND = setOf("pers", "top", "fgsvcl", "fgsvc", "fg")

        private val STATE_NAMES = mapOf(
            "bg" to "in the background",
            "cch" to "cached in the background",
            "gone" to "not running",
        )

        fun describe(ago: Duration): String = when {
            ago < 1.minutes -> "just now"
            ago < 1.hours -> "${ago.inWholeMinutes} min ago"
            ago < 1.days -> "${ago.inWholeHours} h ago"
            ago < 2.days -> "yesterday"
            else -> "${ago.inWholeDays} days ago"
        }
    }
}
