package io.github.capitan0n.droynis.platform

import android.app.usage.StorageStatsManager
import android.content.Context
import android.os.storage.StorageManager
import io.github.capitan0n.droynis.checks.base.StorageProbe
import io.github.capitan0n.droynis.checks.base.StorageSpace
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * The internal volume's size and free space, as Settings › Storage shows them. Unlike per-app
 * storage stats, these two calls need no permission.
 */
internal class AndroidStorage(context: Context) : StorageProbe {

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
}
