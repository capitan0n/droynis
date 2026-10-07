package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.core.Reading

/**
 * One successful read shared by the checks of a scan: a dozen checks ask for the app list at once,
 * and each read costs a binder call per app. Concurrent callers wait for the first read instead of
 * repeating it. [clear] drops the value when the scan ends, so nothing stays in memory between scans.
 */
internal class ScanCache<T> {
    private val lock = Any()
    private var cached: Pair<Long, Reading<T>>? = null

    fun get(read: () -> Reading<T>): Reading<T> = synchronized(lock) {
        val now = System.nanoTime()
        cached?.let { (at, reading) -> if (now - at < MAX_AGE_NANOS) return reading }
        read().also { if (it is Reading.Value) cached = now to it }
    }

    fun clear() = synchronized(lock) { cached = null }

    private companion object {
        /** Long enough for one scan; a new scan reads again. */
        const val MAX_AGE_NANOS = 30_000_000_000L
    }
}
