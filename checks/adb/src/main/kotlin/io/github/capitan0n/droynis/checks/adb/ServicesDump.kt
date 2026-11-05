package io.github.capitan0n.droynis.checks.adb

/** A service running right now, as `dumpsys activity services` lists it. */
data class RunningService(
    val userId: Int,
    val packageName: String,
    /** The class as dumpsys prints it: `.AdService` relative to the package, or a full name. */
    val className: String,
    /** Running as a foreground service (`isForeground=true`), which must show a notification. */
    val foreground: Boolean,
    /**
     * Started with `startService` (`startRequested=true`), so it runs because an app asked, not
     * only while Android or another app is bound to it, as a keyboard's or a plugin's service is.
     */
    val started: Boolean,
)

/**
 * Reads the active services from `dumpsys activity services`, checked against ActiveServices and
 * ServiceRecord in Android 10 to 17, where the `services` command dumps every record in full:
 *
 * ```
 * ACTIVITY MANAGER SERVICES (dumpsys activity services)
 *   User 0 active services:
 *   * ServiceRecord{9f8e7d6 u0 com.example/.AdService c:com.example}
 *     intent={cmp=com.example/.AdService}
 *     packageName=com.example
 *     isForeground=true foregroundId=7 types=0x00000000 foregroundNoti=Notification(…)
 *     startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=1
 * ```
 *
 * Only `* ServiceRecord{…}` lines (active services; pending, restarting and destroyed ones are
 * printed as `* Pending ServiceRecord{…}` and so on) and the two flag lines that follow are used.
 * ServiceRecord prints `isForeground` and `startRequested` only when they are set or were before,
 * so a missing line means false. Intents, notifications and paths are never kept. A record line in
 * any other shape fails the whole parse, so a format change can't hide a service.
 */
object ServicesDump {

    sealed interface Result {
        data class Parsed(val services: List<RunningService>) : Result

        data class Failed(val reason: String) : Result
    }

    private const val HEADER = "ACTIVITY MANAGER SERVICES"

    // Android's regex engine (ICU) wants every literal brace escaped, closing ones too; the JVM's
    // doesn't, so only the instrumented test (AndroidPlatformTest) catches a missing escape.
    private val RECORD_START = Regex("""^\s*\* ServiceRecord\{.*""")
    private val RECORD = Regex(
        """^\s*\* ServiceRecord\{[0-9a-f]+ u(\d+) ([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)/(\S+?)(?: c:\S+)?\}$""",
    )
    private val FOREGROUND = Regex("""^\s+isForeground=(true|false)\b.*""")
    private val STARTED = Regex("""^\s+startRequested=(true|false)\b.*""")

    /** A record's own lines are indented by four spaces or more; anything less ends it. */
    private const val RECORD_INDENT = 4

    fun parse(text: String): Result {
        val lines = text.lines().map { it.trimEnd() }
        if (lines.none { it.trim().startsWith(HEADER) }) return Result.Failed("not the output of dumpsys activity services")

        val services = mutableListOf<RunningService>()
        var unexpected = 0
        var current: RunningService? = null

        fun close() {
            current?.let { services += it }
            current = null
        }

        for (line in lines) {
            when {
                RECORD_START.matches(line) -> {
                    close()
                    val match = RECORD.matchEntire(line)
                    if (match == null) {
                        unexpected++
                    } else {
                        val (user, pkg, cls) = match.destructured
                        current = RunningService(user.toInt(), pkg, cls, foreground = false, started = false)
                    }
                }
                line.isBlank() -> Unit
                line.length - line.trimStart().length < RECORD_INDENT -> close()
                current == null -> Unit
                FOREGROUND.matches(line) -> current = current?.copy(foreground = FOREGROUND.find(line)!!.groupValues[1] == "true")
                STARTED.matches(line) -> current = current?.copy(started = STARTED.find(line)!!.groupValues[1] == "true")
            }
        }
        close()

        return when {
            unexpected > 0 -> Result.Failed("$unexpected service records in an unexpected format")
            // system_server and its apps always run some services; none means the dump was cut or changed.
            services.isEmpty() -> Result.Failed("no running services listed")
            else -> Result.Parsed(services)
        }
    }
}
