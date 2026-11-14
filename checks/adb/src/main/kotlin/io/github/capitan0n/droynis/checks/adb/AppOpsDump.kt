package io.github.capitan0n.droynis.checks.adb

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** The latest time [packageName] used [op] while its app was in [uidState]. */
data class OpAccess(
    val packageName: String,
    /** App-op name as dumpsys prints it, e.g. `CAMERA` or `FINE_LOCATION`. */
    val op: String,
    /** `AppOpsManager` uid state: pers, top, fgsvcl, fgsvc, fg, bg or cch. */
    val uidState: String,
    /** How long before the dump the access happened. */
    val ago: Duration,
)

/**
 * Reads the per-app part of `dumpsys appops`, checked against AppOpsService in Android 17:
 *
 * ```
 * AppOps Uid Op State
 *   Uid u0a123:
 *     Package org.example:
 *       CAMERA (allow):
 *         null=[
 *           Access: [top-s] 2026-10-05 12:00:00.000 (-1h2m3s4ms) duration=+5s0ms
 *         ]
 * ```
 *
 * Only `Uid`, `Package`, op and `Access:` lines are used; the time comes from the relative
 * duration, so the phone's time zone does not matter. One `Access:` line in any other shape fails
 * the whole parse: a format change must never hide an access and turn into a PASS.
 */
object AppOpsDump {

    sealed interface Result {
        data class Parsed(val accesses: List<OpAccess>, val packages: Int) : Result

        data class Failed(val reason: String) : Result
    }

    private const val SECTION = "AppOps Uid Op State"
    // Bracket sets, never \s, \S or \d loops, and a cheap test before each pattern: see DumpLines.kt.
    private val UID = Regex("""^[ \t]*Uid ([^ \t]+):$""")
    private val PACKAGE = Regex("""^[ \t]*Package ([^ \t]+):$""")
    private val OP = Regex("""^[ \t]*([A-Z][A-Z0-9_]*) \([a-z]+(?: / switch [A-Z][A-Z0-9_]*=[a-z]+)?\):$""")
    private val ACCESS = Regex(
        """^[ \t]*Access: \[([a-z]+)-[a-z|]+] [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3} \(([^)]+)\)(?: .*)?$""",
    )

    // android.util.TimeUtils.formatDuration: "-1d2h3m4s5ms", "-5s0ms", "-12ms" or "0".
    private val DURATION = Regex("""([+-])(?:([0-9]+)d)?(?:([0-9]+)h)?(?:([0-9]+)m(?=[0-9]))?(?:([0-9]+)s)?([0-9]+)ms""")

    private val lastParse = LastParse(::read)

    /** Parses [text]; every check reading the same dump in a scan gets the same, single parse. */
    fun parse(text: String): Result = lastParse.of(text)

    private fun read(text: String): Result {
        val lines = dumpLines(text)
        val start = lines.indexOfFirst { it.trim() == SECTION }
            .takeIf { it >= 0 }
            ?: lines.indexOfFirst { isUid(it) }.takeIf { it >= 0 }
            ?: return Result.Failed("no per-app section in the output")

        val accesses = mutableListOf<OpAccess>()
        val packages = mutableSetOf<String>()
        var unexpected = 0
        var pkg: String? = null
        var op: String? = null

        for (line in lines.subList(start, lines.size)) {
            when {
                isUid(line) -> {
                    pkg = null
                    op = null
                }
                line.startsAfterIndent("Package ") && PACKAGE.matches(line) -> {
                    pkg = PACKAGE.find(line)!!.groupValues[1].also { packages += it }
                    op = null
                }
                line.endsWith("):") && OP.matches(line) -> op = if (pkg == null) null else OP.find(line)!!.groupValues[1]
                "Access:" in line -> {
                    val match = ACCESS.find(line)
                    val ago = match?.let { parseDuration(it.groupValues[2]) }
                    if (match == null || ago == null || pkg == null || op == null) {
                        unexpected++
                    } else {
                        // A negative duration is in the past; a positive one means the clock moved.
                        accesses += OpAccess(pkg, op, match.groupValues[1], (-ago).coerceAtLeast(Duration.ZERO))
                    }
                }
            }
        }

        return when {
            unexpected > 0 -> Result.Failed("$unexpected access lines in an unexpected format")
            packages.isEmpty() -> Result.Failed("no apps listed")
            accesses.isEmpty() -> Result.Failed("no access records found")
            else -> Result.Parsed(accesses, packages.size)
        }
    }

    private fun isUid(line: String) = line.startsAfterIndent("Uid ") && UID.matches(line)

    internal fun parseDuration(text: String): Duration? {
        if (text == "0") return Duration.ZERO
        val match = DURATION.matchEntire(text) ?: return null
        val (sign, d, h, m, s, ms) = match.destructured
        val parts = listOf(d, h, m, s, ms).map { it.ifEmpty { "0" }.toLongOrNull() ?: return null }
        val total = parts[0].days + parts[1].hours + parts[2].minutes + parts[3].seconds + parts[4].milliseconds
        return if (sign == "-") -total else total
    }
}
