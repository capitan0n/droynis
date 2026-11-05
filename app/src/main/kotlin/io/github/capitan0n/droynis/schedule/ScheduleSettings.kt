package io.github.capitan0n.droynis.schedule

import android.content.Context
import io.github.capitan0n.droynis.DroynisViewModel
import io.github.capitan0n.droynis.core.CheckSpec
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

/**
 * How often Droynis scans in the background. Android picks the moment within [flex] at the end of
 * each period, and may wait longer to save battery.
 */
enum class ScanInterval(val period: Duration, val flex: Duration) {
    OFF(Duration.ZERO, Duration.ZERO),
    DAILY(1.days, 3.hours),
    WEEKLY(7.days, 12.hours),
}

/** The scheduled scan's settings, in the same file as the app's other settings. */
class ScheduleSettings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(DroynisViewModel.PREFS, Context.MODE_PRIVATE)

    var interval: ScanInterval
        get() = prefs.getString(KEY_INTERVAL, null).let { name -> ScanInterval.entries.firstOrNull { it.name == name } }
            ?: ScanInterval.OFF
        set(value) = prefs.edit().putString(KEY_INTERVAL, value.name).apply()

    /**
     * Every scheduled scan ends with a notification. Off by default: turning it on is what asks
     * Android 13+ for the notification permission. While off, scans run quietly and the app shows
     * the last result.
     */
    var notify: Boolean
        get() = prefs.getBoolean(KEY_NOTIFY, false)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFY, value).apply()

    /**
     * The notification lists what got worse, got fixed or could not run; otherwise it gives only the
     * score and the previous one. On by default.
     */
    var verbose: Boolean
        get() = prefs.getBoolean(KEY_VERBOSE, true)
        set(value) = prefs.edit().putBoolean(KEY_VERBOSE, value).apply()

    /** When the last scheduled scan finished, in epoch milliseconds; null before the first. */
    val lastRun: Long? get() = prefs.getLong(KEY_LAST_RUN, 0L).takeIf { it > 0L }

    /** The last scheduled scan's score; null before the first, or when it had none. */
    val lastScore: Int? get() = prefs.getInt(KEY_LAST_SCORE, -1).takeIf { it >= 0 }

    /** How many checks the last scheduled scan found newly failing. */
    val lastNewIssues: Int get() = prefs.getInt(KEY_LAST_NEW_ISSUES, 0)

    fun recordRun(at: Long, score: Int?, newIssues: Int) {
        prefs.edit()
            .putLong(KEY_LAST_RUN, at)
            .putInt(KEY_LAST_SCORE, score ?: -1)
            .putInt(KEY_LAST_NEW_ISSUES, newIssues)
            .apply()
    }

    /** The root tier switch the app's screens set; a scheduled scan follows it too. */
    val rootEnabled: Boolean get() = prefs.getBoolean(DroynisViewModel.KEY_ROOT, false)

    /** Checks the user muted, by their current ids; left out of the score and of what counts as a change. */
    val muted: Set<String>
        get() = prefs.getStringSet(DroynisViewModel.KEY_MUTED, null).orEmpty().mapTo(HashSet()) { CheckSpec.currentId(it) }

    /** Apps the user trusts: every check still lists them, but none counts them. */
    val trusted: Set<String> get() = prefs.getStringSet(DroynisViewModel.KEY_TRUSTED, null).orEmpty().toSet()

    private companion object {
        const val KEY_INTERVAL = "schedule_interval"
        const val KEY_NOTIFY = "schedule_notify"
        const val KEY_VERBOSE = "schedule_verbose"
        const val KEY_LAST_RUN = "schedule_last_run"
        const val KEY_LAST_SCORE = "schedule_last_score"
        const val KEY_LAST_NEW_ISSUES = "schedule_last_new_issues"
    }
}
