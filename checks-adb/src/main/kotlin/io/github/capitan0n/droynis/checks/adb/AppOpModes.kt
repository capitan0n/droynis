package io.github.capitan0n.droynis.checks.adb

/** An app allowed to use one app-op. */
data class OpGrant(
    /** Null when the dump names only the app's uid: none of its packages has an app-op record. */
    val packageName: String?,
    /** The uid as dumpsys prints it, e.g. `u0a123`. */
    val uid: String,
    /** App-op name as dumpsys prints it, e.g. `SYSTEM_ALERT_WINDOW`. */
    val op: String,
    /** `allow`, or `foreground` for "only while the app is in use". */
    val mode: String,
    /** True when the mode is set for the whole uid rather than for the package. */
    val uidWide: Boolean = false,
)

/**
 * Reads which apps are allowed an app-op from the per-app part of `dumpsys appops`, the same part
 * [AppOpsDump] reads. Checked against AppOpsService in Android 17:
 *
 * ```
 * AppOps Uid Op State
 *   Uid u0a123:
 *     state=cch
 *       MANAGE_EXTERNAL_STORAGE: mode=allow
 *     Package org.example:
 *       SYSTEM_ALERT_WINDOW (allow):
 * ```
 *
 * Android prints a uid mode only when it differs from the op's default, and then it decides for
 * every package of that uid; otherwise the package's own mode decides (`AppOpsService.checkOperation`).
 * A line about a requested op in any other shape fails the parse: a format change must never hide
 * a grant and turn into a PASS.
 */
object AppOpModes {

    sealed interface Result {
        /** [packages] counts every package the dump lists, for the evidence. */
        data class Parsed(val grants: List<OpGrant>, val packages: Int) : Result

        data class Failed(val reason: String) : Result
    }

    /** Modes that let an app use the op: always, or while it is in use. */
    val ALLOWING = setOf("allow", "foreground")

    private const val SECTION = "AppOps Uid Op State"
    private val UID = Regex("""^\s*Uid (\S+):$""")
    private val PACKAGE = Regex("""^\s*Package (\S+):$""")
    private val UID_MODE = Regex("""^\s*([A-Z][A-Z0-9_]*): mode=([a-z]+)$""")
    private val UID_MODE_LIKE = Regex("""^\s*([A-Z][A-Z0-9_]*): mode=""")
    private val OP = Regex("""^\s*([A-Z][A-Z0-9_]*) \(([a-z]+)(?: / switch ([A-Z][A-Z0-9_]*)=([a-z]+))?\):$""")
    private val OP_LIKE = Regex("""^\s*([A-Z][A-Z0-9_]*) \(""")

    /** A package's record of one op: its own mode, or the mode of the switch op that decides for it. */
    private data class PackageMode(val mode: String, val switchOp: String?, val switchMode: String?)

    private class UidBlock(val uid: String) {
        val uidModes = mutableMapOf<String, String>()
        val packages = linkedMapOf<String, MutableMap<String, PackageMode>>()
    }

    /** Apps allowed any of [ops], by the rules `AppOpsService.checkOperation` applies. */
    fun allowed(text: String, ops: Set<String>): Result {
        val lines = text.lines().map { it.trimEnd() }
        // Android 12 and later put the per-app part under a header; older releases start it with
        // the first Uid line, which must then be read too.
        val first = lines.indexOfFirst { it.trim() == SECTION }.takeIf { it >= 0 }?.plus(1)
            ?: lines.indexOfFirst { UID.matches(it) }.takeIf { it >= 0 }
            ?: return Result.Failed("no per-app section in the output")

        val blocks = mutableListOf<UidBlock>()
        var block: UidBlock? = null
        var pkg: MutableMap<String, PackageMode>? = null
        var unexpected = 0
        var firstUnexpected: String? = null
        fun unexpected(line: String) {
            unexpected++
            if (firstUnexpected == null) firstUnexpected = line.trim().take(MAX_QUOTE)
        }

        for (line in lines.subList(first, lines.size)) {
            // Every line of the per-app part is indented; the next part of the dump is not.
            if (line.isNotEmpty() && !line[0].isWhitespace()) break
            when {
                UID.matches(line) -> {
                    block = UidBlock(UID.find(line)!!.groupValues[1]).also { blocks += it }
                    pkg = null
                }
                PACKAGE.matches(line) -> {
                    val name = PACKAGE.find(line)!!.groupValues[1]
                    pkg = block?.packages?.getOrPut(name) { mutableMapOf() }
                    if (pkg == null) unexpected(line)
                }
                OP.matches(line) -> {
                    val (op, mode, switchOp, switchMode) = OP.find(line)!!.destructured
                    val record = PackageMode(mode, switchOp.ifEmpty { null }, switchMode.ifEmpty { null })
                    val current = pkg
                    if (current != null) current[op] = record else if (op in ops) unexpected(line)
                }
                UID_MODE.matches(line) -> {
                    val (op, mode) = UID_MODE.find(line)!!.destructured
                    val current = block
                    // Uid modes come before the uid's packages; anywhere else the line would be misread.
                    if (current != null && pkg == null) current.uidModes[op] = mode else if (op in ops) unexpected(line)
                }
                else -> {
                    val near = OP_LIKE.find(line) ?: UID_MODE_LIKE.find(line)
                    if (near != null && near.groupValues[1] in ops) unexpected(line)
                }
            }
        }

        if (unexpected > 0) {
            return Result.Failed("$unexpected app-op lines in an unexpected format, the first: \"$firstUnexpected\"")
        }
        if (blocks.isEmpty()) return Result.Failed("no apps listed")
        return Result.Parsed(blocks.flatMap { grantsIn(it, ops) }, blocks.sumOf { it.packages.size })
    }

    private fun grantsIn(block: UidBlock, ops: Set<String>): List<OpGrant> = ops.flatMap { op ->
        val uidMode = block.uidModes[op]
        if (uidMode != null) {
            // A uid mode that differs from the default decides for every package of the uid.
            if (uidMode !in ALLOWING) return@flatMap emptyList()
            val names = block.packages.keys.ifEmpty { setOf(null) }
            names.map { OpGrant(it, block.uid, op, uidMode, uidWide = true) }
        } else {
            block.packages.mapNotNull { (name, modes) ->
                val record = modes[op] ?: return@mapNotNull null
                // A switch op decides for this one, through its own uid or package mode.
                val switch = record.switchOp
                val mode = when {
                    switch == null -> record.mode
                    block.uidModes[switch] != null -> block.uidModes.getValue(switch)
                    else -> record.switchMode ?: record.mode
                }
                if (mode in ALLOWING) OpGrant(name, block.uid, op, mode) else null
            }
        }
    }

    /**
     * The uid `UserHandle.formatUid` printed, e.g. 10123 for `u0a123` or 1010005 for `u10a5`; null for
     * shapes that are not app uids.
     */
    fun uidOf(label: String): Int? {
        val app = Regex("""u(\d+)a(\d+)""").matchEntire(label) ?: return null
        val user = app.groupValues[1].toIntOrNull() ?: return null
        val appId = app.groupValues[2].toIntOrNull() ?: return null
        return user * PER_USER_RANGE + FIRST_APPLICATION_UID + appId
    }

    private const val PER_USER_RANGE = 100_000

    /** How much of an unexpected line the failure quotes, enough to fix the parser from a report. */
    private const val MAX_QUOTE = 100
    private const val FIRST_APPLICATION_UID = 10_000
}
