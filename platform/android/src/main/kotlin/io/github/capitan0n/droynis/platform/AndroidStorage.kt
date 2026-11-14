package io.github.capitan0n.droynis.platform

import android.app.usage.StorageStatsManager
import android.content.Context
import android.os.storage.StorageManager
import io.github.capitan0n.droynis.checks.base.RemovableVolume
import io.github.capitan0n.droynis.checks.base.StorageProbe
import io.github.capitan0n.droynis.checks.base.StorageSpace
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * The internal volume's size and free space, as Settings › Storage shows them, and the SD cards and
 * USB drives in use. Unlike per-app storage stats, these calls need no permission.
 */
internal class AndroidStorage(private val context: Context) : StorageProbe {

    private val stats: StorageStatsManager? = context.getSystemService(StorageStatsManager::class.java)

    override fun internal(): Reading<StorageSpace> {
        val source = Source("StorageStatsManager.getTotalBytes() and getFreeBytes(), internal volume")
        return probe(source) {
            val manager = stats ?: return@probe Reading.Unsupported("no storage stats service", source)
            val total = manager.getTotalBytes(StorageManager.UUID_DEFAULT)
            val free = manager.getFreeBytes(StorageManager.UUID_DEFAULT)
            Reading.Value(StorageSpace(totalBytes = total, freeBytes = free), source)
        }
    }

    override fun removableVolumes(): Reading<List<RemovableVolume>> {
        val source = Source("StorageManager.getStorageVolumes(): removable, not emulated")
        return probe(source) {
            val manager = context.getSystemService(StorageManager::class.java)
                ?: return@probe Reading.Unsupported("no storage service", source)
            // A portable volume is removable and holds its own files; an adopted SD card only shows up
            // as the emulated storage on top of it. The volume's UUID is left out: it names the card.
            val volumes = manager.storageVolumes
                .filter { it.isRemovable && !it.isEmulated }
                .map { volume ->
                    RemovableVolume(
                        description = volume.getDescription(context)?.takeIf { it.isNotBlank() } ?: "Removable storage",
                        state = volume.state.orEmpty(),
                    )
                }
            Reading.Value(volumes, source)
        }
    }
}
