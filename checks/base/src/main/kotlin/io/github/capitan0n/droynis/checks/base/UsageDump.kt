package io.github.capitan0n.droynis.checks.base

import java.time.Instant

/**
 * What Droynis' privileged usage reader prints: after the [HEADER] line, one line per app that
 * brought a screen to the front, as `app=<package> times=<count> last=<epoch milliseconds>`. A line
 * `error=…` replaces them when the history could not be read. Counts only: the events themselves
 * never leave the reader.
 */
object UsageDump {
    const val HEADER = "droynis-usage 1"

    sealed interface Result {
        data class Parsed(val screens: Map<String, ScreenUse>) : Result

        data class Failed(val reason: String) : Result
    }

    /** One line of the dump for [use]. */
    fun line(use: ScreenUse): String = "app=${use.packageName} times=${use.times} last=${use.lastShown.toEpochMilli()}"

    /** A line in another shape fails the whole read: a format change must never hide an app. */
    fun parse(text: String): Result {
        val lines = text.lines().map { it.trim() }
        val start = lines.indexOf(HEADER)
        if (start < 0) {
            val said = lines.filter { it.isNotEmpty() }.joinToString(" ").take(MAX_QUOTE)
            return Result.Failed(if (said.isEmpty()) "the reader printed nothing" else "unexpected output: $said")
        }
        val body = lines.drop(start + 1).filter { it.isNotEmpty() }
        body.firstOrNull { it.startsWith("error=") }?.let { return Result.Failed(it.removePrefix("error=").take(MAX_QUOTE)) }
        val screens = HashMap<String, ScreenUse>()
        for (line in body) {
            val match = ROW.matchEntire(line) ?: return Result.Failed("an unexpected line: ${line.take(MAX_QUOTE)}")
            val (pkg, times, last) = match.destructured
            val count = times.toIntOrNull() ?: return Result.Failed("an unexpected count: ${line.take(MAX_QUOTE)}")
            val at = last.toLongOrNull() ?: return Result.Failed("an unexpected time: ${line.take(MAX_QUOTE)}")
            screens[pkg] = ScreenUse(pkg, count, Instant.ofEpochMilli(at))
        }
        return Result.Parsed(screens)
    }

    private val ROW = Regex("""app=(\S+) times=(\d+) last=(\d+)""")
    private const val MAX_QUOTE = 120
}
