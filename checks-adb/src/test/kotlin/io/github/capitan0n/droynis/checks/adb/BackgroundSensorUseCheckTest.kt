package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class BackgroundSensorUseCheckTest {

    private val source = Source("dumpsys appops", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 10, 5, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun check(
        dump: Reading<String>,
        apps: Reading<List<InstalledApp>> = Reading.Value(APPS, Source("fake")),
    ) = BackgroundSensorUseCheck(
        dumpsys = object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump
        },
        packages = object : PackageInventory {
            override fun installedApps() = apps
            override fun label(packageName: String) = LABELS[packageName] ?: packageName
        },
    )

    private fun dump(vararg lines: String) = Reading.Value(
        "AppOps Uid Op State\n" + lines.joinToString("\n"),
        source,
    )

    @Test
    fun `needs the adb tier`() {
        val spec = check(dump()).spec
        assertEquals(setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
    }

    @Test
    fun `passes when sensors were used only in the foreground`() = runTest {
        val outcome = check(
            dump(
                *app("org.example.maps", "FINE_LOCATION", "top", "-1h0m0s0ms"),
                *app("org.example.recorder", "RECORD_AUDIO", "fgsvc", "-5m0s0ms"),
            ),
        ).run(context)

        assertEquals(Status.PASS, outcome.status)
    }

    @Test
    fun `background location by a user app fails at notice level`() = runTest {
        val outcome = check(dump(*app("org.example.maps", "FINE_LOCATION", "bg", "-3h0m0s0ms"))).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("1 app used location from the background: Maps", outcome.summary)
        val line = outcome.evidence.single { it.label == "Location" }
        assertEquals("Maps (org.example.maps)", line.value)
        assertEquals("last used 3 h ago, in the background", line.note)
    }

    @Test
    fun `background microphone use escalates to warning`() = runTest {
        val outcome = check(
            dump(
                *app("org.example.recorder", "RECORD_AUDIO", "cch", "-2d0h0m0s0ms"),
                *app("org.example.maps", "COARSE_LOCATION", "bg", "-1m0s0ms"),
            ),
        ).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals("2 apps used the microphone and location from the background: Recorder and Maps", outcome.summary)
    }

    @Test
    fun `system apps and accesses older than a week are ignored`() = runTest {
        val outcome = check(
            dump(
                *app("com.android.phone", "RECORD_AUDIO", "bg", "-1h0m0s0ms"),
                *app("org.example.maps", "FINE_LOCATION", "bg", "-8d0h0m0s0ms"),
            ),
        ).run(context)

        assertEquals(Status.PASS, outcome.status)
    }

    @Test
    fun `an app missing from the app list still counts`() = runTest {
        val outcome = check(dump(*app("org.example.work", "CAMERA", "bg", "-1h0m0s0ms"))).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
    }

    @Test
    fun `an unknown app state counts as background`() = runTest {
        val outcome = check(dump(*app("org.example.maps", "FINE_LOCATION", "idle", "-1h0m0s0ms"))).run(context)

        assertEquals(Status.FAIL, outcome.status)
    }

    @Test
    fun `never passes on output it cannot read`() = runTest {
        val denied = Reading.Unavailable("Permission Denial: can't dump appops", source)
        assertEquals(Status.UNKNOWN, check(denied).run(context).status)
        assertEquals(Status.UNSUPPORTED, check(Reading.Unsupported("no appops service", source)).run(context).status)

        val garbled = dump("  Uid u0a1:", "    Package org.example.maps:", "      FINE_LOCATION (allow):", "        Access: bg")
        assertEquals(Status.UNKNOWN, check(garbled).run(context).status)
    }

    @Test
    fun `without the app list background use is unknown, not a pass`() = runTest {
        val outcome = check(
            dump(*app("org.example.maps", "FINE_LOCATION", "bg", "-1h0m0s0ms")),
            apps = Reading.Unavailable("denied", Source("fake")),
        ).run(context)

        assertEquals(Status.UNKNOWN, outcome.status)
        assertTrue("app list" in outcome.summary)
    }

    private fun app(pkg: String, op: String, state: String, ago: String) = arrayOf(
        "  Uid u0a${pkg.length}:",
        "    Package $pkg:",
        "      $op (allow):",
        "        null=[",
        "          Access: [$state-s] 2026-10-05 11:00:00.000 ($ago)",
        "        ]",
    )

    private companion object {
        val APPS = listOf(
            InstalledApp("org.example.maps", isSystem = false, isDebuggable = false, installer = null, targetSdk = 36),
            InstalledApp("org.example.recorder", isSystem = false, isDebuggable = false, installer = null, targetSdk = 36),
            InstalledApp("com.android.phone", isSystem = true, isDebuggable = false, installer = null, targetSdk = 37),
        )
        val LABELS = mapOf("org.example.maps" to "Maps", "org.example.recorder" to "Recorder")
    }
}
