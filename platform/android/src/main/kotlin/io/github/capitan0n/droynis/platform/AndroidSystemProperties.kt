package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.checks.base.SystemProperties
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.util.concurrent.TimeUnit

/**
 * Runs `/system/bin/getprop` once and parses its "[name]: [value]" lines. SELinux decides what an
 * app may read; properties it may not are left out of the output. No hidden API is used.
 */
internal object AndroidSystemProperties : SystemProperties {

    private val LINE = Regex("""^\[([^\]]+)]: \[(.*)]$""")
    private val source = Source("/system/bin/getprop")

    // Several checks read properties in the same scan, most of them at its start: one process serves
    // them all, and the others wait for it instead of starting their own.
    private val lock = Any()
    private var cached: Pair<Long, Reading<Map<String, String>>>? = null

    override fun all(): Reading<Map<String, String>> = synchronized(lock) {
        val now = System.nanoTime()
        cached?.let { (at, reading) -> if (now - at < CACHE_NANOS) return reading }
        read().also { cached = now to it }
    }

    private fun read(): Reading<Map<String, String>> = probe(source) {
        val process = ProcessBuilder("/system/bin/getprop").redirectErrorStream(true).start()
        try {
            val output = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(5, TimeUnit.SECONDS)
            val props = output.lineSequence()
                .mapNotNull { LINE.find(it.trim()) }
                .associate { it.groupValues[1] to it.groupValues[2] }
            if (props.isEmpty()) Reading.Unavailable("getprop printed nothing", source) else Reading.Value(props, source)
        } finally {
            process.destroy()
        }
    }

    private const val CACHE_NANOS = 10_000_000_000L
}
