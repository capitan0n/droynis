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
    ;

    /**
     * A scheduled scan that starts later than this after the one before (or after the schedule
     * began) ran late: past the window Android gives itself, plus the longest gap Doze leaves
     * between its maintenance windows.
     */
    val lateAfter: Duration get() = period + flex + DOZE_GRACE

    private companion object {
        val DOZE_GRACE = 6.hours
    }
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

    /** By when the next scheduled scan should have started, in epoch milliseconds; null before timing began. */
    private val dueBy: Long? get() = prefs.getLong(KEY_DUE_BY, 0L).takeIf { it > 0L }

    /**
     * Whether scheduled scans run late: the last one JobScheduler started was late, or the next one
     * is overdue now. Android or the phone's battery saver held Droynis back, or the phone was off.
     */
    fun late(now: Long): Boolean {
        if (interval == ScanInterval.OFF) return false
        val due = dueBy
        return prefs.getBoolean(KEY_RAN_LATE, false) || (due != null && now > due)
    }

    /** A new job: the first scan is due within [ScanInterval.lateAfter] of [now]. */
    fun startTiming(now: Long, interval: ScanInterval) {
        prefs.edit()
            .putLong(KEY_DUE_BY, now + interval.lateAfter.inWholeMilliseconds)
            .putBoolean(KEY_RAN_LATE, false)
            .apply()
    }

    /**
     * JobScheduler ran the scan that started at [startedAt]: records whether it was late, and when
     * the next one is due. Not for scans the user starts ("Run one now").
     */
    fun recordJobRun(startedAt: Long) {
        val interval = interval
        if (interval == ScanInterval.OFF) return
        prefs.edit()
            .putBoolean(KEY_RAN_LATE, ranLate(startedAt, dueBy))
            .putLong(KEY_DUE_BY, startedAt + interval.lateAfter.inWholeMilliseconds)
            .apply()
    }

    /** No schedule, nothing to time. */
    fun clearTiming() {
        prefs.edit().remove(KEY_DUE_BY).remove(KEY_RAN_LATE).apply()
    }

    /** The root tier switch the app's screens set; a scheduled scan follows it too. */
    val rootEnabled: Boolean get() = prefs.getBoolean(DroynisViewModel.KEY_ROOT, false)

    /** Checks the user muted, by their current ids; left out of the score and of what counts as a change. */
    val muted: Set<String>
        get() = prefs.getStringSet(DroynisViewModel.KEY_MUTED, null).orEmpty().mapTo(HashSet()) { CheckSpec.currentId(it) }

    /** Apps the user trusts: every check still lists them, but none counts them. */
    val trusted: Set<String> get() = prefs.getStringSet(DroynisViewModel.KEY_TRUSTED, null).orEmpty().toSet()

    internal companion object {
        private const val KEY_INTERVAL = "schedule_interval"
        private const val KEY_NOTIFY = "schedule_notify"
        private const val KEY_VERBOSE = "schedule_verbose"
        private const val KEY_LAST_RUN = "schedule_last_run"
        private const val KEY_LAST_SCORE = "schedule_last_score"
        private const val KEY_LAST_NEW_ISSUES = "schedule_last_new_issues"
        private const val KEY_DUE_BY = "schedule_due_by"
        private const val KEY_RAN_LATE = "schedule_ran_late"

        /** A scan that started after it was [dueBy] ran late; with no due time yet, it can't have. */
        fun ranLate(startedAt: Long, dueBy: Long?): Boolean = dueBy != null && startedAt > dueBy
    }
}
