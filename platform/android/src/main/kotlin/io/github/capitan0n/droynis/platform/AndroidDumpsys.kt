package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.checks.adb.Dumpsys
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.io.Reader
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Runs `/system/bin/dumpsys` as Droynis itself. The service checks our permissions (DUMP, and for
 * some services PACKAGE_USAGE_STATS) and answers "Permission Denial" without them. No hidden API
 * is used; the binary is the same one adb runs.
 */
internal object AndroidDumpsys : Dumpsys {

    private const val DUMPSYS = "/system/bin/dumpsys"

    override fun dump(service: String, vararg args: String): Reading<String> {
        val source = Source((listOf("dumpsys", service) + args).joinToString(" "), Grant.DUMP)
        return probe(source) {
            val process = ProcessBuilder(listOf(DUMPSYS, service) + args).redirectErrorStream(true).start()
            try {
                process.outputStream.close()
                val result = process.inputStream.bufferedReader().use { readDumpsys(it, source) }
                process.waitFor(5, TimeUnit.SECONDS)
                result
            } finally {
                process.destroy()
            }
        }
    }
}

/**
 * Runs dumpsys as Droynis while it holds the adb grants, and otherwise through a privileged shell
 * (Shizuku or root) while one is ready: both cover the ADB tier.
 */
internal class RoutedDumpsys(
    private val grants: AndroidGrants,
    private val shells: ShellRouter,
) : Dumpsys {

    // Seven ADB-tier checks read `dumpsys appops` in the same scan: one read serves them all, so
    // they judge the same snapshot and the phone prints a few MB once instead of seven times.
    // One lock per command, so `dumpsys trust` never waits for a slow `dumpsys appops`.
    private val locks = ConcurrentHashMap<String, Any>()
    private val cached = ConcurrentHashMap<String, Pair<Long, Reading<String>>>()

    override fun dump(service: String, vararg args: String): Reading<String> {
        val key = (listOf(service) + args).joinToString(" ")
        return synchronized(locks.computeIfAbsent(key) { Any() }) {
            val now = System.nanoTime()
            cached[key]?.let { (at, reading) -> if (now - at < CACHE_NANOS) return reading }
            read(service, *args).also { if (it is Reading.Value) cached[key] = now to it }
        }
    }

    /** Drops the outputs kept for one scan, so they don't stay in memory between scans. */
    fun clear() = cached.clear()

    private fun read(service: String, vararg args: String): Reading<String> {
        val ownGrants = grants.detect().containsAll(setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS))
        val shell = if (ownGrants || args.isNotEmpty()) null else shells.active()
        return shell?.dumpsys(service) ?: AndroidDumpsys.dump(service, *args)
    }

    private companion object {
        /** Long enough for one scan; a new scan reads again. */
        const val CACHE_NANOS = 30_000_000_000L
    }
}

// dumpsys appops on a phone with a few hundred apps prints a few MB at most.
private const val MAX_CHARS = 16 * 1024 * 1024

/** Reads dumpsys output up to a size limit and turns refusals into readings without a value. */
internal fun readDumpsys(reader: Reader, source: Source): Reading<String> {
    val text = StringBuilder()
    val buffer = CharArray(64 * 1024)
    while (true) {
        val n = reader.read(buffer)
        if (n < 0) break
        text.appendRange(buffer, 0, n)
        if (text.length > MAX_CHARS) return Reading.Unavailable("output longer than $MAX_CHARS characters", source)
    }
    val firstLine = text.lineSequence().firstOrNull { it.isNotBlank() }?.trim().orEmpty()
    return when {
        firstLine.isEmpty() -> Reading.Unavailable("dumpsys printed nothing", source)
        firstLine.startsWith("Permission Denial") -> Reading.Unavailable(firstLine, source)
        firstLine.startsWith("Can't find service") -> Reading.Unsupported(firstLine, source)
        else -> Reading.Value(text.toString(), source)
    }
}
