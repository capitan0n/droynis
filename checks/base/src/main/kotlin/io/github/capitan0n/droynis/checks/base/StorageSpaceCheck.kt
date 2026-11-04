package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import java.util.Locale

class StorageSpaceCheck(private val storage: StorageProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1090",
        category = Category.DEVICE_INTEGRITY,
        title = "Storage space",
        severity = Severity.NOTICE,
        explanation = "System updates are downloaded and unpacked on the phone before they install, and need " +
            "free space for that. On a nearly full phone, security updates, app updates and WebView updates " +
            "fail or wait until space is freed, so known flaws stay open for longer.",
        remediation = Remediation(
            text = "Open Settings › Storage and free up space: uninstall apps you don't use, delete downloads you " +
                "no longer need, and move photos and videos to a computer or your own server. Then install " +
                "pending system updates.",
            settingsActions = listOf(SettingsActions.INTERNAL_STORAGE),
        ),
        failsWhen = "more than 80% of the internal storage is in use",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val reading = storage.internal()
        val evidence = listOf(reading.toEvidence("Internal storage") { describe(it) })
        return reading.evaluate("The storage space", evidence) { space ->
            val percent = usedPercent(space)
                ?: return@evaluate Outcome.unknown("The storage size is not plausible", evidence)
            val summary = "Storage is $percent% full (${size(space.freeBytes)} free)"
            if (percent > LIMIT_PERCENT) Outcome.fail(summary, evidence) else Outcome.pass(summary, evidence)
        }
    }

    private fun describe(space: StorageSpace): String {
        val percent = usedPercent(space) ?: return "${space.freeBytes} of ${space.totalBytes} bytes free"
        return "$percent% used: ${size(space.freeBytes)} free of ${size(space.totalBytes)}"
    }

    companion object {
        const val LIMIT_PERCENT = 80

        /**
         * The share in use as a whole percent, rounded up, so it shows above 80 exactly when more
         * than 80% is in use. Null when the numbers can't be right.
         */
        fun usedPercent(space: StorageSpace): Int? {
            val (total, free) = space
            if (total <= 0 || free < 0 || free > total) return null
            val used = total - free
            return ((used * 100 + total - 1) / total).toInt()
        }

        /** "850 MB", "23.4 GB" or "128 GB", in the decimal units Android's Settings uses. */
        fun size(bytes: Long): String = when {
            bytes < GB -> "${bytes / MB} MB"
            bytes < 100 * GB -> "%.1f GB".format(Locale.ROOT, bytes.toDouble() / GB)
            else -> "%.0f GB".format(Locale.ROOT, bytes.toDouble() / GB)
        }

        private const val MB = 1_000_000L
        private const val GB = 1_000_000_000L
    }
}
