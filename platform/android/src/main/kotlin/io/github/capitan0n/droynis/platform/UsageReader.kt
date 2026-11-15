package io.github.capitan0n.droynis.platform

import android.annotation.SuppressLint
import android.app.usage.UsageEvents
import android.os.IBinder
import android.os.Process
import io.github.capitan0n.droynis.checks.base.ScreenUse
import io.github.capitan0n.droynis.checks.base.UsageDump
import java.lang.reflect.InvocationTargetException
import java.time.Instant
import kotlin.system.exitProcess

/**
 * Reads which apps brought a screen to the front, as the shell user or root: both may read the usage
 * history, which an app may only with the user's Usage access switch. So with Shizuku or root
 * connected, SUSP-5003 runs without that switch, and Droynis never changes it.
 *
 * Like [TelephonyReader] it never runs in the app: Droynis' Shizuku shell calls [read], and the root
 * shell starts [main] in an `app_process` for one read. It asks the usage stats service for the
 * events since a time, keeps a count and the latest time per app, and prints only those
 * ([UsageDump]'s format): the events themselves stay in this process.
 *
 * The service is an internal API, reached by reflection. Android's hidden-API restrictions apply to
 * app processes only, and this code never runs in one.
 */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi", "SoonBlockedPrivateApi", "BlockedPrivateApi")
object UsageReader {

    /** Entry point for `app_process`: the start time in epoch milliseconds is the only argument. */
    @JvmStatic
    fun main(args: Array<String>) {
        println(read(args.firstOrNull()?.toLongOrNull() ?: -1L))
        System.out.flush()
        // Binder threads could keep the process alive; the root shell waits for it to end.
        exitProcess(0)
    }

    fun read(sinceMillis: Long): String = buildString {
        appendLine(UsageDump.HEADER)
        try {
            require(sinceMillis >= 0) { "no start time" }
            val shown = HashMap<String, ScreenUse>()
            val events = query(sinceMillis, System.currentTimeMillis())
            val event = UsageEvents.Event()
            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.eventType != ACTIVITY_RESUMED) continue
                val packageName = event.packageName ?: continue
                // The dump is one app per line, fields apart by a space: a name that can't be one is left out.
                if (!PACKAGE.matches(packageName)) continue
                val at = Instant.ofEpochMilli(event.timeStamp)
                val before = shown[packageName]
                shown[packageName] = if (before == null) {
                    ScreenUse(packageName, 1, at)
                } else {
                    before.copy(times = before.times + 1, lastShown = maxOf(before.lastShown, at))
                }
            }
            shown.values.sortedBy { it.packageName }.forEach { appendLine(UsageDump.line(it)) }
        } catch (e: Exception) {
            appendLine("error=${describe(e)}")
        }
    }.trimEnd()

    /**
     * `IUsageStatsManager.queryEvents(begin, end, callingPackage)`, unchanged since Android 5. The
     * service returns null to a caller it refuses.
     */
    private fun query(begin: Long, end: Long): UsageEvents {
        val binder = Class.forName("android.os.ServiceManager").getMethod("getService", String::class.java)
            .invoke(null, "usagestats") as IBinder? ?: throw IllegalStateException("no usagestats service")
        val api = Class.forName("android.app.usage.IUsageStatsManager")
        val service = Class.forName("android.app.usage.IUsageStatsManager\$Stub")
            .getMethod("asInterface", IBinder::class.java).invoke(null, binder)
            ?: throw IllegalStateException("the usagestats service has no IUsageStatsManager interface")
        val queryEvents = api.getMethod("queryEvents", Long::class.javaPrimitiveType, Long::class.javaPrimitiveType, String::class.java)
        val events = try {
            queryEvents.invoke(service, begin, end, callerPackage())
        } catch (e: InvocationTargetException) {
            throw (e.targetException as? Exception ?: e)
        }
        return events as UsageEvents? ?: throw IllegalStateException("the usage stats service refused the read")
    }

    /** The package name app-ops knows this process's uid by: the shell's, or "root" for uid 0. */
    private fun callerPackage(): String = if (Process.myUid() == ROOT_UID) "root" else SHELL_PACKAGE

    private fun describe(e: Exception): String = "${e.javaClass.simpleName}: ${e.message}".replace('\n', ' ').take(MAX_ERROR)

    /** `UsageEvents.Event.ACTIVITY_RESUMED` (Android 10); the same value was `MOVE_TO_FOREGROUND` before. */
    private const val ACTIVITY_RESUMED = 1
    private const val ROOT_UID = 0
    private const val SHELL_PACKAGE = "com.android.shell"
    private val PACKAGE = Regex("[A-Za-z0-9_.]+")
    private const val MAX_ERROR = 200
}
