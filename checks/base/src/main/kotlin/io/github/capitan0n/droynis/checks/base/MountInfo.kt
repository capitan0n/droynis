package io.github.capitan0n.droynis.checks.base

/** One mount as `/proc/<pid>/mountinfo` lists it (proc(5)). */
data class Mount(
    /** The filesystem's device, "major:minor": a bind mount shares it with what it shows. */
    val device: String,
    /** The directory of that filesystem that is mounted here. */
    val root: String,
    val mountPoint: String,
    val fsType: String,
)

/**
 * Reads `/proc/self/mountinfo`, a stable kernel format:
 * `36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue`. Paths escape a
 * space, tab, newline or backslash as an octal `\040`. A line in another shape fails the whole parse,
 * so a mount is never missed in silence.
 */
object MountInfo {

    /** The mounts in [text], in order; null when any line is not a mountinfo line. */
    fun parse(text: String): List<Mount>? = text.lines().filter { it.isNotBlank() }.map { line ->
        val fields = line.trim().split(' ')
        val dash = fields.indexOf("-")
        // Six fixed fields, optional ones, the separator, then the filesystem type and source.
        if (fields.size < MIN_FIELDS || dash < FIXED_FIELDS || dash + 2 >= fields.size) return null
        Mount(device = fields[2], root = unescape(fields[3]), mountPoint = unescape(fields[4]), fsType = fields[dash + 1])
    }

    private val OCTAL = Regex("""\\([0-7]{3})""")

    private fun unescape(path: String): String = OCTAL.replace(path) { it.groupValues[1].toInt(8).toChar().toString() }

    private const val FIXED_FIELDS = 6
    private const val MIN_FIELDS = 9
}
