package io.github.capitan0n.droynis.checks.adb

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

enum class PrivacySensor(val id: Int, val label: String) {
    CAMERA(2, "Camera"),
    MICROPHONE(1, "Microphone"),
}

class SensorPrivacyCheck(
    private val dumpsys: Dumpsys,
    private val supported: () -> Reading<Set<PrivacySensor>>,
) : Check {
    override val spec = CheckSpec(
        id = "APPS-4113",
        category = Category.APPS,
        title = "Camera and microphone privacy switches",
        severity = Severity.INFO,
        minSdk = 31,
        requires = setOf(Grant.DUMP),
        explanation = "Android's privacy switches can block camera and microphone access across apps. " +
            "This reports the software switches for this profile, independently of which apps have permissions.",
        remediation = Remediation(
            text = "Review Camera access and Microphone access in Privacy controls or Quick Settings.",
            settingsActions = listOf(SettingsActions.PRIVACY_CONTROLS, SettingsActions.PRIVACY),
        ),
        failsWhen = "never (reports the camera and microphone privacy switches)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val sensors = supported()
        val availability = sensors.toEvidence("Supported privacy switches") { it.joinToString { sensor -> sensor.label } }
        if (sensors is Reading.Unsupported || sensors is Reading.Value && sensors.value.isEmpty()) {
            return Outcome.unsupported("This device has no supported camera or microphone privacy switches", listOf(availability))
        }
        if (sensors !is Reading.Value) return Outcome.unknown("Could not verify which privacy switches are supported", listOf(availability))
        val userId = context.appUid?.div(100_000)
            ?: return Outcome.unknown("Could not identify the scanned profile", listOf(availability))
        val dump = dumpsys.dump("sensor_privacy")
        if (dump !is Reading.Value) {
            return Outcome.unknown("Could not read the privacy switches", listOf(availability, dump.toEvidence("Sensor privacy")))
        }
        val blocked = SensorPrivacyDump.parse(dump.value, userId, context.sdkInt)
        val states = sensors.value.sorted().map { sensor ->
            val value = when (blocked?.get(sensor.id)) {
                true -> "blocked"
                false -> "allowed by this switch"
                null -> null
            }
            Evidence("${sensor.label} access", value, dump.source, note = if (value == null) "switch state unavailable" else null)
        }
        val evidence = listOf(availability) + states
        if (states.any { it.value == null }) return Outcome.unknown("Could not verify all privacy switches", evidence)
        return Outcome.pass(states.joinToString(", ") { "${it.label}: ${it.value}" }, evidence)
    }
}

internal object SensorPrivacyDump {
    // Android 12 wrote booleans directly under the user. Later builds record separate toggle types.
    fun parse(text: String, userId: Int, sdk: Int): Map<Int, Boolean?>? {
        val lines = dumpLines(text).filter { it.isNotBlank() }
        if (lines.size < 4 || lines[0] != "SENSOR PRIVACY MANAGER STATE (dumpsys sensor_privacy)" ||
            lines[1] != "{" || lines.last() != "}") return null
        val root = DumpBlock(lines.subList(2, lines.lastIndex), lines[2].takeWhile { it == ' ' })
        val users = root.records("users") ?: return null
        if (users.any { it.field("user_id")?.toIntOrNull() == null }) return null
        val profiles = users.filter { it.field("user_id")?.toIntOrNull() == userId }
        if (profiles.size > 1) return null
        val profile = profiles.singleOrNull()
        val state = if (sdk <= 32 && root.field("storage_implementation") == null) {
            if (root.keys() != setOf("users") || profile == null ||
                profile.field("is_enabled")?.toBooleanStrictOrNull() == null ||
                (profile.keys() - setOf("user_id", "is_enabled", "individual_enabled_sensor")).isNotEmpty()) return null
            legacy(profile) ?: return null
        } else {
            if (root.field("storage_implementation") != STORAGE ||
                (root.keys() - setOf("storage_implementation", "users")).isNotEmpty()) return null
            if (profile == null) emptyMap() else modern(profile) ?: return null
        }
        // In these recognized formats Android starts a software toggle unblocked until a state is recorded.
        return PrivacySensor.entries.associate { it.id to state.getOrDefault(it.id, false) }
    }

    private fun legacy(profile: DumpBlock): Map<Int, Boolean?>? {
        val switches = profile.records("individual_enabled_sensor") ?: return null
        val results = mutableMapOf<Int, Boolean?>()
        for (switch in switches) {
            val sensor = switch.field("sensor")?.toIntOrNull() ?: return null
            if (sensor in results) return null
            results[sensor] = switch.field("is_enabled")?.toBooleanStrictOrNull()
        }
        return results
    }

    private fun modern(profile: DumpBlock): Map<Int, Boolean?>? {
        if ((profile.keys() - setOf("user_id", "sensors")).isNotEmpty()) return null
        val sensors = profile.records("sensors") ?: return null
        val results = mutableMapOf<Int, Boolean?>()
        for (sensor in sensors) {
            val id = sensor.field("sensor")?.toIntOrNull() ?: return null
            if (id in results) return null
            val toggles = sensor.records("toggles") ?: return null
            if (toggles.any { it.field("toggle_type") !in setOf("1", "2") }) return null
            val software = toggles.singleOrNull { it.field("toggle_type") == "1" }
            // Some releases dump only one toggle per sensor. A hardware entry can obscure the software state.
            results[id] = when (software?.field("state_type")) {
                "1" -> true
                "2" -> false
                else -> null
            }
        }
        return results
    }

    private const val STORAGE = "com.android.server.sensorprivacy.SensorPrivacyStateControllerImpl"
}
