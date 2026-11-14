package io.github.capitan0n.droynis.checks.adb

import java.lang.ref.WeakReference

/*
 * How the dumpsys parsers keep regex matching cheap.
 *
 * On Android, Regex runs on ICU, whose matcher backtracks on a stack it keeps on the native heap.
 * `\s*`, `\S+` and `\d+` push a frame for every character they consume, and lazy quantifiers can,
 * while a greedy bracket set (`[ \t]*`, `[^ \t]+`, `[0-9]+`) or `.*` scans in constant space. Eleven checks
 * parsing a multi-megabyte `dumpsys appops` at once that way ran a phone out of memory: Droynis
 * aborted, and Android killed other apps, VPNs among them, on the way (issue #15).
 *
 * So the parsers write patterns with bracket sets, never `\s`, `\S` or `\d` loops; read lines
 * through [dumpLines], which bounds what any pattern can consume; test a line cheaply before
 * running a pattern on it; and share one parse of a dump through [LastParse].
 */

/** The longest line the parsers look at; the lines they read are far shorter. */
internal const val MAX_LINE = 4_096

/** Ends a cut line, so a pattern that ends a record with `$` can't match what is left of it. */
private const val CUT = '…'

/** [text]'s lines without trailing whitespace, each cut to [MAX_LINE] characters. */
internal fun dumpLines(text: String): List<String> = text.lines().map { line ->
    val trimmed = line.trimEnd()
    if (trimmed.length <= MAX_LINE) trimmed else trimmed.take(MAX_LINE) + CUT
}

/** Whether this line starts with [prefix] after its indentation: a cheap test before a pattern. */
internal fun String.startsAfterIndent(prefix: String): Boolean {
    var start = 0
    while (start < length && (this[start] == ' ' || this[start] == '\t')) start++
    return startsWith(prefix, start)
}

/**
 * The last parse of one dump. `RoutedDumpsys` hands every check of a scan the same String, so the
 * checks reading one dump parse it once instead of each on its own, all at the same time: the first
 * one parses while the others wait for its result. The dump itself is held weakly, so it can leave
 * memory after the scan.
 */
internal class LastParse<T : Any>(private val parse: (String) -> T) {
    private var text = WeakReference<String>(null)
    private var result: T? = null

    @Synchronized
    fun of(text: String): T {
        result?.let { if (this.text.get() === text) return it }
        return parse(text).also {
            this.text = WeakReference(text)
            result = it
        }
    }
}
