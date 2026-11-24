package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence

class ScreenCaptureCheck(private val dumpsys: Dumpsys, private val packages: PackageInventory) : Check {
    override val spec = CheckSpec(
        id = "SUSP-5105",
        category = Category.SUSPICIOUS_APPS,
        title = "Active screen capture",
        severity = Severity.WARNING,
        explanation = "This checks Android's MediaProjection service for a screen capture session during the scan. " +
            "It can see sessions for the whole screen or a single app, including when Droynis is off screen. " +
            "A session can be used to record or share the screen. Capture methods outside this service are beyond this check.",
        remediation = Remediation(
            "If you didn't start this, open the notification shade and tap Stop on the recording or sharing notice. " +
                "If someone asked you to share your screen unexpectedly, end the call.",
        ),
        requires = setOf(Grant.DUMP),
        failsWhen = "Android's MediaProjection service reports an active screen capture or mirroring session",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = dumpsys.dump("media_projection")
        if (dump !is Reading.Value) {
            return Outcome.unknown("Could not read Android's screen capture status", listOf(dump.toEvidence("MediaProjection")))
        }

        // AOSP prints one grant at most. A presentation grant doesn't capture the screen.
        val lines = dumpLines(dump.value).map(String::trimStart).filter(String::isNotEmpty)
        if (lines.size != 3 || lines[0] != HEADER || lines[1] != "Media Projection:") return unrecognized(dump)
        val record = lines[2]
        if (record == "null") {
            return Outcome.pass("Android reports no active screen capture session",
                listOf(Evidence("MediaProjection", "no active session", dump.source)))
        }
        val (pkg, kind) = PROJECTION.matchEntire(record)?.destructured ?: return unrecognized(dump)
        if (kind == "TYPE_PRESENTATION") {
            return Outcome.pass("Android reports no active screen capture session",
                listOf(Evidence("MediaProjection", "presentation session", dump.source)))
        }
        val label = packages.label(pkg)
        return Outcome.fail("Android reports an active capture session from $label",
            listOf(Evidence("Capture app", "$label ($pkg)", dump.source, packageName = pkg)))
    }

    private fun unrecognized(dump: Reading.Value<String>) = Outcome.unknown(
        "Android's screen capture status was unrecognized",
        listOf(Evidence("MediaProjection", null, dump.source, note = "unrecognized service output")),
    )

    private companion object {
        const val HEADER = "MEDIA PROJECTION MANAGER (dumpsys media_projection)"
        val PROJECTION = Regex("""\(([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*), uid=[0-9]+\): (TYPE_SCREEN_CAPTURE|TYPE_MIRRORING|TYPE_PRESENTATION)""")
    }
}
