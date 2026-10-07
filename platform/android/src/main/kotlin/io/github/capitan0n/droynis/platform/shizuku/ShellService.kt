package io.github.capitan0n.droynis.platform.shizuku

import android.os.ParcelFileDescriptor
import io.github.capitan0n.droynis.platform.TelephonyReader
import java.io.IOException
import java.io.Reader
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/**
 * Droynis' read-only shell. Shizuku starts it in a process of its own that runs as the shell user
 * (as root when Shizuku itself was started with root), creates it by class name, and hands its
 * binder to the app.
 *
 * Every method runs one fixed, read-only command with checked arguments, or, for [telephony], a fixed
 * set of telephony getters. There is deliberately no general "run this" call, so whatever reaches this
 * binder can only ask for these reads. It runs outside the app process, so it must not use the app's
 * state; [TelephonyReader] keeps none.
 *
 * Failures reach the app as IllegalArgumentException or IllegalStateException, the exceptions a
 * binder call carries back.
 */
class ShellService : IShellService.Stub() {

    /** Shizuku calls this when it stops the service, for example when the app unbinds or dies. */
    override fun destroy() {
        exitProcess(0)
    }

    override fun readSetting(table: String?, key: String?, userId: Int): String? {
        require(table != null && table in TABLES) { "unknown settings table" }
        require(key != null && KEY.matches(key)) { "invalid settings key" }
        require(userId >= 0) { "invalid user" }
        val value = run(listOf(SETTINGS, "--user", userId.toString(), "get", table, key)).removeSuffix("\n")
        // `settings get` prints "null" for a key that is not set.
        return value.takeUnless { it == "null" }
    }

    override fun selinuxMode(): String = run(listOf(GETENFORCE)).trim()

    override fun telephony(): String = TelephonyReader.read()

    override fun dumpsys(service: String?): ParcelFileDescriptor {
        require(service != null && service in DUMPSYS_SERVICES) { "dumpsys service not allowed" }
        val process = start(listOf(DUMPSYS, service), DUMPSYS_TIMEOUT_SECONDS)
        val (read, write) = try {
            ParcelFileDescriptor.createPipe()
        } catch (e: IOException) {
            process.destroy()
            throw IllegalStateException("could not create a pipe: ${e.message}")
        }
        thread(name = "droynis-dumpsys", isDaemon = true) {
            try {
                ParcelFileDescriptor.AutoCloseOutputStream(write).use { out ->
                    process.inputStream.use { it.copyTo(out) }
                }
            } catch (e: IOException) {
                // The app stopped reading early, for example at its size limit.
            } finally {
                process.destroy()
            }
        }
        // Returning it hands the read end to the app and closes this process's copy.
        return read
    }

    /** Starts [command] without a shell and kills it if it runs longer than [timeoutSeconds]. */
    private fun start(command: List<String>, timeoutSeconds: Long): Process {
        val process = try {
            ProcessBuilder(command).redirectErrorStream(true).start()
        } catch (e: IOException) {
            throw IllegalStateException("${command.first()} could not run: ${e.message}")
        }
        try {
            process.outputStream.close()
        } catch (e: IOException) {
            // Nothing is ever written to it; a failed close changes nothing.
        }
        // A hung command must not hold a binder thread for good.
        thread(name = "droynis-timeout", isDaemon = true) {
            try {
                if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) process.destroyForcibly()
            } catch (e: InterruptedException) {
                process.destroyForcibly()
            }
        }
        return process
    }

    /** Runs [command] to the end and returns what it printed; fails on a non-zero exit. */
    private fun run(command: List<String>): String {
        val process = start(command, COMMAND_TIMEOUT_SECONDS)
        try {
            val output = try {
                process.inputStream.bufferedReader().use(::readLimited)
            } catch (e: IOException) {
                throw IllegalStateException("could not read the output: ${e.message}")
            }
            val exit = process.waitFor()
            val name = command.first().substringAfterLast('/')
            check(exit == 0) { "$name exited with code $exit: ${output.trim().take(MAX_ERROR)}" }
            return output
        } catch (e: InterruptedException) {
            throw IllegalStateException("interrupted")
        } finally {
            process.destroy()
        }
    }

    private fun readLimited(reader: Reader): String {
        val text = StringBuilder()
        val buffer = CharArray(4096)
        while (true) {
            val n = reader.read(buffer)
            if (n < 0) return text.toString()
            text.appendRange(buffer, 0, n)
            check(text.length <= MAX_OUTPUT) { "output longer than $MAX_OUTPUT characters" }
        }
    }

    private companion object {
        const val SETTINGS = "/system/bin/settings"
        const val GETENFORCE = "/system/bin/getenforce"
        const val DUMPSYS = "/system/bin/dumpsys"

        val TABLES = setOf("global", "secure", "system")

        /** Settings keys are lower case with digits and underscores; a few use dots or dashes. */
        val KEY = Regex("[a-z0-9_.-]{1,100}")

        val DUMPSYS_SERVICES = setOf("appops", "trust")

        const val COMMAND_TIMEOUT_SECONDS = 10L
        const val DUMPSYS_TIMEOUT_SECONDS = 30L
        const val MAX_OUTPUT = 64 * 1024
        const val MAX_ERROR = 200
    }
}
