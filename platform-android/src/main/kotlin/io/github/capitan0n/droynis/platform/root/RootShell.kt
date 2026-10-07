package io.github.capitan0n.droynis.platform.root

import android.content.Context
import android.os.Process
import io.github.capitan0n.droynis.checks.root.ProcNet
import io.github.capitan0n.droynis.checks.root.RootManager
import io.github.capitan0n.droynis.checks.root.RootModules
import io.github.capitan0n.droynis.checks.root.RootShellProbe
import io.github.capitan0n.droynis.checks.root.TrustedComputersCheck
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.platform.ShellAccess
import io.github.capitan0n.droynis.platform.TelephonyReader
import io.github.capitan0n.droynis.platform.readDumpsys
import java.io.File
import java.io.IOException
import java.io.StringReader
import java.io.Writer
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Where the root tier stands for Droynis. */
enum class RootState {
    /** Off in Droynis, the default: su is never run. */
    OFF,

    /** Turned on; the root manager is asked at the next scan. */
    ON,

    /** The last root shell ran as root. */
    GRANTED,

    /** The root manager refused, or didn't answer in time. */
    DENIED,

    /** There is no su to run. */
    NO_SU,
}

data class RootStatus(
    val state: RootState,
    /** The root manager root itself reported, once a shell ran. */
    val manager: RootManager? = null,
    /** A root manager app Droynis can see without root, by name. */
    val managerApp: String? = null,
    /** An su file Droynis can see without root. */
    val suVisible: Boolean = false,
    /** Why the last attempt failed. */
    val error: String? = null,
)

/**
 * The opt-in root tier: a root shell from `su`, opened for a scan and closed after it, that runs
 * only the fixed, read-only commands below. Nothing outside this class chooses a command or a
 * path; the only arguments, a settings table and key, are checked against a fixed set and a strict
 * pattern.
 */
class RootShell(context: Context) : RootShellProbe, ShellAccess {

    private val app = context.applicationContext
    private val lock = Any()

    /** The user turned the root tier on in Droynis. Until then su is never run. */
    @Volatile
    var enabled = false

    @Volatile
    private var session: Session? = null

    @Volatile
    private var lastResult: RootState? = null

    @Volatile
    private var lastError: String? = null

    @Volatile
    private var detected: RootManager? = null

    override val isReady: Boolean get() = session?.alive == true

    /** Root is on and the last shell ran as root, so the root checks can run. */
    val granted: Boolean get() = enabled && lastResult == RootState.GRANTED

    /** The root tier's state, without running su. */
    fun status(): RootStatus {
        val state = if (!enabled) RootState.OFF else lastResult ?: RootState.ON
        return RootStatus(
            state = state,
            manager = detected,
            managerApp = MANAGER_APPS.entries.firstOrNull { app.packageManager.getLaunchIntentForPackage(it.key) != null }?.value,
            suVisible = SU_PATHS.any { File(it).exists() },
            error = lastError.takeIf { state == RootState.DENIED || state == RootState.NO_SU },
        )
    }

    /**
     * Opens the root shell if root is on. The first time, the root manager asks the user, so this
     * waits up to [timeoutMillis]; never call it on the main thread.
     */
    fun open(timeoutMillis: Long = OPEN_TIMEOUT_MILLIS): Boolean {
        if (!enabled) return false
        synchronized(lock) {
            if (session?.alive == true) return true
            val started = try {
                Session.start()
            } catch (e: IOException) {
                lastResult = RootState.NO_SU
                lastError = e.message
                return false
            }
            when (val id = started.run(ID, timeoutMillis)) {
                is Session.Result.Done -> if (id.exit != 0 || id.output.trim() != "0") {
                    started.close()
                    lastResult = RootState.DENIED
                    lastError = "su answered as uid ${id.output.trim().take(20)}, not as root"
                    return false
                }
                is Session.Result.Failed -> {
                    started.close()
                    lastResult = RootState.DENIED
                    lastError = id.reason
                    return false
                }
            }
            session = started
            lastResult = RootState.GRANTED
            lastError = null
            detected = (started.run(MANAGER, COMMAND_TIMEOUT_MILLIS) as? Session.Result.Done)?.let { managerOf(it.output) }
            return true
        }
    }

    /** Ends the root shell. Root stays on for the next scan. */
    fun close() {
        synchronized(lock) {
            session?.close()
            session = null
        }
    }

    /** Turns root off, ends the shell and forgets the last result. */
    fun disable() {
        enabled = false
        close()
        lastResult = null
        lastError = null
    }

    override fun adbKeys(): Reading<String?> =
        read("cat ${TrustedComputersCheck.ADB_KEYS}", ifExists(TrustedComputersCheck.ADB_KEYS)) { exit, output, source ->
            when (exit) {
                0 -> Reading.Value(output, source)
                MISSING -> Reading.Value(null, source)
                else -> failed(exit, output, source)
            }
        }

    override fun modules(): Reading<String> =
        read("list /data/adb/modules", MODULES) { exit, output, source ->
            if (exit == 0) Reading.Value(output, source) else failed(exit, output, source)
        }

    override fun manager(): Reading<RootManager> {
        detected?.let { return Reading.Value(it, Source("su: root manager", Grant.ROOT)) }
        return read("root manager", MANAGER) { exit, output, source ->
            if (exit == 0) Reading.Value(managerOf(output), source) else failed(exit, output, source)
        }
    }

    override fun magiskPolicies(): Reading<String> =
        read("magisk --sqlite", MAGISK_POLICIES) { exit, output, source ->
            if (exit == 0) Reading.Value(output, source) else failed(exit, output, source)
        }

    override fun procNet(table: ProcNet): Reading<String> {
        val path = "/proc/net/${table.file}"
        return read("cat $path", ifExists(path)) { exit, output, source ->
            when (exit) {
                0 -> Reading.Value(output, source)
                MISSING -> Reading.Unsupported("this kernel has no $path", source)
                else -> failed(exit, output, source)
            }
        }
    }

    override fun readSetting(table: String, key: String): Reading<String?> {
        if (table !in TABLES || !KEY.matches(key)) {
            return Reading.Unavailable("not an allowed setting", Source("su: settings get", Grant.ROOT))
        }
        val user = Process.myUid() / PER_USER_RANGE
        return read("settings get $table $key", "settings --user $user get $table $key") { exit, output, source ->
            if (exit == 0) Reading.Value(output.trim().takeUnless { it == "null" }, source) else failed(exit, output, source)
        }
    }

    override fun selinuxMode(): Reading<String> =
        read("getenforce", "getenforce") { exit, output, source ->
            if (exit == 0) Reading.Value(output.trim(), source) else failed(exit, output, source)
        }

    override fun dumpsys(service: String): Reading<String> {
        if (service !in DUMPSYS_SERVICES) {
            return Reading.Unavailable("not an allowed dumpsys service", Source("su: dumpsys", Grant.ROOT))
        }
        return read("dumpsys $service", "dumpsys $service", DUMPSYS_TIMEOUT_MILLIS) { _, output, source ->
            readDumpsys(StringReader(output), source)
        }
    }

    /**
     * Runs [TelephonyReader] as root in an `app_process` with Droynis' own APK as its class path, the
     * way Shizuku starts its server. The only variable part, the APK path, is Android's own and is
     * checked against a strict pattern.
     */
    override fun telephony(): Reading<String> {
        val apk = app.applicationInfo.sourceDir.orEmpty()
        val main = TelephonyReader::class.java.name
        if (!APK_PATH.matches(apk) || !CLASS_NAME.matches(main)) {
            return Reading.Unavailable("unexpected app path", Source("su: app_process", Grant.ROOT))
        }
        val command = "CLASSPATH='$apk' /system/bin/app_process /system/bin $main"
        return read("app_process (telephony service)", command, TELEPHONY_TIMEOUT_MILLIS) { exit, output, source ->
            if (exit == 0) Reading.Value(output, source) else failed(exit, output, source)
        }
    }

    /** Runs one fixed [command] in the open shell and maps its exit code and output. */
    private inline fun <T> read(
        label: String,
        command: String,
        timeoutMillis: Long = COMMAND_TIMEOUT_MILLIS,
        map: (exit: Int, output: String, source: Source) -> Reading<T>,
    ): Reading<T> {
        val source = Source("su: $label", Grant.ROOT)
        synchronized(lock) {
            val shell = session?.takeIf { it.alive } ?: return Reading.Unavailable("the root shell is not open", source)
            return when (val result = shell.run(command, timeoutMillis)) {
                is Session.Result.Done -> map(result.exit, result.output, source)
                is Session.Result.Failed -> {
                    if (!shell.alive) session = null
                    Reading.Unavailable(result.reason, source)
                }
            }
        }
    }

    private fun failed(exit: Int, output: String, source: Source): Reading<Nothing> =
        Reading.Unavailable("exit code $exit: ${output.trim().take(MAX_ERROR)}", source)

    /**
     * One `su` process with a shell reading commands from its stdin. Each command ends with a line
     * holding a random marker and the exit code, which no file Droynis reads can contain.
     */
    private class Session private constructor(private val process: java.lang.Process) {

        sealed interface Result {
            data class Done(val exit: Int, val output: String) : Result

            data class Failed(val reason: String) : Result
        }

        private val marker = "@@droynis-${UUID.randomUUID()}"
        private val lines = LinkedBlockingQueue<Any>()
        private val stdin: Writer = process.outputStream.bufferedWriter()

        @Volatile
        var alive = true
            private set

        init {
            thread(name = "droynis-su", isDaemon = true) {
                try {
                    process.inputStream.bufferedReader().use { reader ->
                        while (true) lines.put(reader.readLine() ?: break)
                    }
                } catch (e: IOException) {
                    // The shell ended; the end marker below says so.
                } finally {
                    alive = false
                    lines.put(EOF)
                }
            }
        }

        fun run(command: String, timeoutMillis: Long): Result {
            if (!alive) return Result.Failed("the root shell has ended")
            try {
                // No command may read the session's own stdin, so each gets /dev/null.
                stdin.write("{\n$command\n} </dev/null 2>&1\nprintf '\\n%s %s\\n' '$marker' \"\$?\"\n")
                stdin.flush()
            } catch (e: IOException) {
                close()
                return Result.Failed("the root shell has ended: ${e.message}")
            }
            val collected = ArrayList<String>()
            var chars = 0L
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            while (true) {
                val left = deadline - System.nanoTime()
                val next = if (left > 0) lines.poll(left, TimeUnit.NANOSECONDS) else null
                when {
                    next == null -> {
                        close()
                        return Result.Failed("no answer within ${timeoutMillis / 1000} seconds")
                    }
                    next === EOF -> {
                        alive = false
                        val said = collected.joinToString(" ").trim().take(MAX_ERROR)
                        return Result.Failed(said.ifEmpty { "the root shell ended" })
                    }
                    next is String && next.startsWith("$marker ") -> {
                        val exit = next.removePrefix("$marker ").trim().toIntOrNull()
                            ?: return Result.Failed("unexpected end of output")
                        if (chars > MAX_CHARS) return Result.Failed("output longer than $MAX_CHARS characters")
                        // The marker line starts with a newline of its own; drop the blank line it leaves.
                        if (collected.lastOrNull()?.isEmpty() == true) collected.removeAt(collected.lastIndex)
                        return Result.Done(exit, collected.joinToString("\n"))
                    }
                    next is String -> {
                        chars += next.length + 1
                        if (chars <= MAX_CHARS) collected += next else collected.clear()
                    }
                }
            }
        }

        fun close() {
            alive = false
            try {
                stdin.write("exit\n")
                stdin.flush()
                stdin.close()
            } catch (e: IOException) {
                // Already ended.
            }
            process.destroy()
        }

        companion object {
            private val EOF = Any()

            /** `su` from PATH: Magisk, KernelSU and APatch all answer there. */
            fun start(): Session = Session(ProcessBuilder("su").redirectErrorStream(true).start())
        }
    }

    private companion object {
        const val ID = "id -u"
        const val MANAGER = "if command -v magisk >/dev/null 2>&1; then echo magisk; " +
            "elif [ -e /data/adb/ksud ]; then echo kernelsu; elif [ -e /data/adb/apd ]; then echo apatch; " +
            "else echo other; fi"
        const val MAGISK_POLICIES = "magisk --sqlite 'SELECT uid, policy, until FROM policies'"

        /** Lists /data/adb/modules in the format [RootModules.parse] reads. */
        val MODULES = "for d in /data/adb/modules/*; do [ -d \"\$d\" ] || continue; " +
            "echo \"${RootModules.MODULE}\${d##*/}\"; " +
            "[ -e \"\$d/disable\" ] && echo ${RootModules.DISABLED}; " +
            "[ -e \"\$d/remove\" ] && echo ${RootModules.REMOVE}; " +
            "cat \"\$d/module.prop\" 2>/dev/null; echo; done; true"

        /** Exit code [ifExists] uses for a missing file. */
        const val MISSING = 3

        fun ifExists(path: String) = "( [ -e $path ] || exit $MISSING; cat $path )"

        fun managerOf(output: String): RootManager = when (output.trim()) {
            "magisk" -> RootManager.MAGISK
            "kernelsu" -> RootManager.KERNELSU
            "apatch" -> RootManager.APATCH
            else -> RootManager.OTHER
        }

        val TABLES = setOf("global", "secure", "system")
        val KEY = Regex("[a-z0-9_.-]{1,100}")
        val DUMPSYS_SERVICES = setOf("appops", "trust")

        /** Manager apps by package; a hidden (renamed) Magisk app is not among them. */
        val MANAGER_APPS = linkedMapOf(
            "com.topjohnwu.magisk" to "Magisk",
            "io.github.huskydg.magisk" to "Kitsune Mask",
            "me.weishu.kernelsu" to "KernelSU",
            "com.rifsxd.ksunext" to "KernelSU Next",
            "com.sukisu.ultra" to "SukiSU Ultra",
            "me.bmax.apatch" to "APatch",
        )
        val SU_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/debug_ramdisk/su", "/su/bin/su")

        const val OPEN_TIMEOUT_MILLIS = 30_000L
        const val COMMAND_TIMEOUT_MILLIS = 10_000L
        const val DUMPSYS_TIMEOUT_MILLIS = 30_000L

        /** Starting a Java process takes a second or two on older phones. */
        const val TELEPHONY_TIMEOUT_MILLIS = 20_000L

        /**
         * Android installs apps under /data/app, or /mnt/expand/<volume>/app on adopted storage; the path
         * may hold `~`, `=` and base64 characters, never a quote.
         */
        val APK_PATH = Regex("(/data/app|/mnt/expand/[A-Za-z0-9-]+/app)/[A-Za-z0-9._~=+/-]+\\.apk")
        val CLASS_NAME = Regex("[A-Za-z0-9_.$]+")
        const val MAX_CHARS = 16L * 1024 * 1024
        const val MAX_ERROR = 200
        const val PER_USER_RANGE = 100_000
    }
}
