package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class ScreenCaptureCheckTest {
    private val source = Source("dumpsys media_projection", Grant.SHIZUKU)
    private val context = ScanContext(ZonedDateTime.now(), sdkInt = 35, appPackage = "io.github.capitan0n.droynis")
    private val header = "MEDIA PROJECTION MANAGER (dumpsys media_projection)\nMedia Projection: \n"

    private suspend fun outcome(reading: Reading<String>) = ScreenCaptureCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String): Reading<String> {
                assertEquals("media_projection", service)
                return reading
            }
        },
        object : PackageInventory {
            override fun installedApps(): Reading<List<InstalledApp>> = error("unused")
            override fun label(packageName: String) = "Recorder"
        },
    ).run(context)

    private suspend fun outcome(record: String) = outcome(Reading.Value(header + record, source))

    @Test
    fun `confirmed capture and mirroring name the initiating app`() = runTest {
        for (type in listOf("TYPE_SCREEN_CAPTURE", "TYPE_MIRRORING")) {
            val finding = outcome("(org.example.recorder, uid=10234): $type")
            assertEquals(Status.FAIL, finding.status)
            assertEquals("Android reports an active capture session from Recorder", finding.summary)
            assertEquals("org.example.recorder", finding.evidence.single().packageName)
        }
    }

    @Test
    fun `idle and presentation sessions do not report screen capture`() = runTest {
        assertEquals(Status.PASS, outcome("null\n").status)
        assertEquals(Status.PASS, outcome("(org.example.slides, uid=10234): TYPE_PRESENTATION").status)
    }

    @Test
    fun `unavailable and incomplete service data stay unknown`() = runTest {
        assertEquals(Status.UNKNOWN, outcome(Reading.Unavailable("permission denied", source)).status)
        assertEquals(Status.UNKNOWN, outcome(Reading.Unsupported("service missing", source)).status)
        assertEquals(Status.UNKNOWN, outcome("(org.example.recorder, uid=10234):").status)
        assertEquals(Status.UNKNOWN, outcome(Reading.Value("null\n", source)).status)
    }
}
