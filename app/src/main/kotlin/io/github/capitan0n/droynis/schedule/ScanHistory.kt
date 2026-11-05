package io.github.capitan0n.droynis.schedule

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.IOException

/**
 * The last scan's [ScanSnapshot], in Droynis' private storage outside backups. Kept only while a
 * schedule is on: turning it off deletes the file.
 */
object ScanHistory {
    private const val FILE_NAME = "last-scan.txt"
    private val lock = Any()

    private fun file(context: Context) = AtomicFile(File(context.noBackupFilesDir, FILE_NAME))

    fun load(context: Context): ScanSnapshot? = synchronized(lock) {
        try {
            ScanSnapshot.decode(file(context).readFully().decodeToString())
        } catch (e: IOException) {
            null // no snapshot yet
        }
    }

    /**
     * Saves [snapshot] as the latest, keeping the last result of checks that could not run now,
     * and returns the snapshot it replaced.
     */
    fun record(context: Context, snapshot: ScanSnapshot): ScanSnapshot? {
        synchronized(lock) {
            val previous = load(context)
            val target = file(context)
            val out = try {
                target.startWrite()
            } catch (e: IOException) {
                return previous
            }
            try {
                out.write(snapshot.carryingOver(previous).encode().toByteArray())
                target.finishWrite(out)
            } catch (e: IOException) {
                target.failWrite(out)
            }
            return previous
        }
    }

    fun clear(context: Context) {
        synchronized(lock) { file(context).delete() }
    }
}
