package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

/**
 * SD cards and USB drives in use as portable storage. Android encrypts internal storage and SD cards
 * formatted as internal storage (adopted), but never a portable volume: it is FAT32 or exFAT, which
 * any computer reads. `StorageManager.getStorageVolumes()` lists volumes with no permission; an
 * adopted card shows up there only as the emulated storage on top of it, so it is never counted.
 */
class RemovableStorageCheck(private val storage: StorageProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1091",
        category = Category.DEVICE_INTEGRITY,
        title = "Unencrypted SD card or USB drive",
        severity = Severity.NOTICE,
        explanation = "Android encrypts the phone's internal storage, but not an SD card or USB drive used as " +
            "portable storage: anyone who takes the card can read its photos, downloads and backups on any " +
            "computer, and on the phone every app with access to media or all files reads them too. An SD card " +
            "formatted as internal storage, where the phone offers it, is encrypted with a key that never leaves " +
            "this phone, so it is unreadable anywhere else.",
        remediation = Remediation(
            text = "Keep private files off portable cards and drives, and eject the ones you don't use. If the " +
                "phone offers it, format the SD card as internal storage under Settings › Storage › the card › " +
                "⋮ › Format as internal; this erases the card and ties it to this phone, so copy its files off " +
                "first.",
            settingsActions = listOf(SettingsActions.INTERNAL_STORAGE),
        ),
        failsWhen = "an SD card or USB drive is mounted as portable storage, which Android doesn't encrypt",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val volumes = storage.removableVolumes()
        val evidence = when (volumes) {
            is Reading.Value -> volumes.value.map { Evidence("Removable storage", it.description, volumes.source, note = stateNote(it)) }
                .ifEmpty { listOf(Evidence("Removable storage", "none", volumes.source)) }
            else -> listOf(volumes.toEvidence("Removable storage"))
        }
        return volumes.evaluate("The list of SD cards and USB drives", evidence) { all ->
            val mounted = all.filter { it.mounted }
            when {
                mounted.isNotEmpty() -> Outcome.fail(
                    "${count(mounted.size, "SD card or USB drive is", "SD cards or USB drives are")} in use without " +
                        "encryption: ${mounted.map { it.description }.joinNames()}",
                    evidence,
                )
                all.isEmpty() -> Outcome.pass("No SD card or USB drive is in use as portable storage", evidence)
                else -> Outcome.pass("No portable SD card or USB drive is mounted", evidence)
            }
        }
    }

    private fun stateNote(volume: RemovableVolume): String = when (volume.state) {
        RemovableVolume.MOUNTED -> "mounted, not encrypted"
        RemovableVolume.MOUNTED_READ_ONLY -> "mounted read-only, not encrypted"
        else -> "not mounted (${volume.state})"
    }
}
