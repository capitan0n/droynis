package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.PermissionProbe
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class PrivacyAccessChecksTest {
    private val context = ScanContext(ZonedDateTime.now(), sdkInt = 35, appUid = 10150)
    private val source = Source("test", Grant.SHIZUKU)
    private fun dump(result: Reading<String>) = object : Dumpsys {
        override fun dump(service: String, vararg args: String) = result
    }

    @Test
    fun `full-screen access uses defaults and explicit denials including shared UID overrides`() = runTest {
        val appOps = """
            AppOps Uid Op State
              Uid u0a121:
                Package org.example.denied:
                  USE_FULL_SCREEN_INTENT (ignore):
              Uid u0a122:
                Package org.example.granted:
                  USE_FULL_SCREEN_INTENT (allow):
              Uid u0a123:
                USE_FULL_SCREEN_INTENT: mode=deny
                Package org.example.shared:
                  USE_FULL_SCREEN_INTENT (allow):
        """.trimIndent()
        fun app(suffix: String, uid: Int, target: Int = 35, enabled: Boolean = true) =
            InstalledApp("org.example.$suffix", false, false, null, target, isEnabled = enabled, uid = uid)

        val packages = object : PackageInventory {
            override fun label(packageName: String) = packageName.substringAfterLast('.')

            override fun installedApps() = Reading.Value(listOf(
                app("default", 10120), app("denied", 10121), app("granted", 10122), app("shared", 10123),
                app("otherShared", 10123), app("legacy", 10124, target = 28),
                app("missingPermission", 10125), app("disabled", 10126, enabled = false),
            ), source)
        }
        val permissions = object : PermissionProbe {
            override fun holders(permissions: Set<String>) = Reading.Value(
                listOf("default", "denied", "shared", "otherShared", "disabled")
                    .associate { "org.example.$it" to permissions }, source,
            )
        }
        val outcome = FullScreenAlertsCheck(dump(Reading.Value(appOps, source)), packages, permissions).run(context)
        assertEquals(Status.PASS, outcome.status)
        assertEquals(listOf("org.example.default", "org.example.granted", "org.example.legacy"),
            outcome.evidence.mapNotNull { it.packageName })
        val unexpected = appOps.replace("(ignore)", "(unknown)")
        assertEquals(Status.UNKNOWN, FullScreenAlertsCheck(dump(Reading.Value(unexpected, source)), packages, permissions)
            .run(context).status)
    }

    @Test
    fun `modern privacy dump reports only the scanned profile and recognizes default state`() = runTest {
        assertEquals(mapOf(1 to true, 2 to false), SensorPrivacyDump.parse(MODERN_DUMP, 0, 35))
        assertEquals(mapOf(1 to false, 2 to false), SensorPrivacyDump.parse(MODERN_DUMP, 11, 35))
        assertNull(SensorPrivacyDump.parse(MODERN_DUMP.dropLast(1), 0, 35))
        assertNull(SensorPrivacyDump.parse(MODERN_DUMP.replace("sensors=", "unknown_sensors="), 0, 35))

        fun check(result: Reading<String>) =
            SensorPrivacyCheck(dump(result)) { Reading.Value(PrivacySensor.entries.toSet(), source) }
        val outcome = check(Reading.Value(MODERN_DUMP, source)).run(context)
        assertEquals(Status.PASS, outcome.status)
        assertEquals("blocked", outcome.evidence.single { it.label == "Microphone access" }.value)
        val hardwareOnly = MODERN_DUMP.replace("toggle_type=1", "toggle_type=2")
        assertEquals(Status.UNKNOWN, check(Reading.Value(hardwareOnly, source)).run(context).status)
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("denied", source)).run(context).status)
    }

    @Test
    fun `Android 12 privacy booleans are read without accepting malformed records`() {
        val legacy = """
            SENSOR PRIVACY MANAGER STATE (dumpsys sensor_privacy)
            {
              users={
                user_id=0
                is_enabled=false
                individual_enabled_sensor={
                  sensor=2
                  is_enabled=true
                }
              }
            }
        """.trimIndent()
        assertEquals(mapOf(1 to false, 2 to true), SensorPrivacyDump.parse(legacy, 0, 31))
        assertNull(SensorPrivacyDump.parse(legacy, 10, 31))
        assertEquals(mapOf(1 to false, 2 to null), SensorPrivacyDump.parse(legacy.replace("enabled=true", "enabled=??"), 0, 31))
    }

    private companion object {
        val MODERN_DUMP = """
            SENSOR PRIVACY MANAGER STATE (dumpsys sensor_privacy)
            {
              storage_implementation=com.android.server.sensorprivacy.SensorPrivacyStateControllerImpl
              users=[
                {
                  user_id=0
                  sensors={
                    sensor=1
                    toggles={
                      toggle_type=1
                      state_type=1
                      last_change=15
                    }
                  }
                }
                {
                  user_id=10
                  sensors={
                    sensor=2
                    toggles={
                      toggle_type=1
                      state_type=1
                      last_change=16
                    }
                  }
                }
              ]
            }
        """.trimIndent()
    }
}
