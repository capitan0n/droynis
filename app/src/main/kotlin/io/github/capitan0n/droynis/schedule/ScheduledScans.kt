package io.github.capitan0n.droynis.schedule

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import io.github.capitan0n.droynis.SharedPlatform
import io.github.capitan0n.droynis.allChecks
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.platform.AndroidPlatform
import io.github.capitan0n.droynis.platform.shizuku.ShizukuState
import io.github.capitan0n.droynis.report.HardeningIndex
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** What a scheduled scan found, for the app to show. */
data class ScheduledScanSummary(val score: Int?, val newIssues: Int)

/**
 * Background scans through Android's JobScheduler: no extra library, and no permission beyond
 * RECEIVE_BOOT_COMPLETED, which keeps the schedule across reboots.
 */
object ScheduledScans {
    /** Also for testing: `adb shell cmd jobscheduler run -f io.github.capitan0n.droynis 1`. */
    const val JOB_ID = 1

    private val scanner by lazy { Scanner() }

    private const val SHIZUKU_WAIT_STEPS = 16
    private val SHIZUKU_WAIT_STEP = 250.milliseconds

    /**
     * Schedules, changes or cancels the periodic scan. Leaves a job that already matches alone:
     * scheduling it again would restart its period, and the app calls this at every start, which
     * also brings the job back after a force stop. False when JobScheduler refused.
     */
    fun apply(context: Context, interval: ScanInterval): Boolean {
        val scheduler = context.getSystemService(JobScheduler::class.java) ?: return false
        if (interval == ScanInterval.OFF) {
            scheduler.cancel(JOB_ID)
            return true
        }
        val periodMillis = interval.period.inWholeMilliseconds
        val pending = scheduler.getPendingJob(JOB_ID)
        if (pending != null && pending.isPeriodic && pending.intervalMillis == periodMillis) return true
        val job = JobInfo.Builder(JOB_ID, ComponentName(context, ScheduledScanService::class.java))
            .setPeriodic(periodMillis, interval.flex.inWholeMilliseconds)
            .setPersisted(true)
            .setRequiresBatteryNotLow(true)
            .build()
        return try {
            scheduler.schedule(job) == JobScheduler.RESULT_SUCCESS
        } catch (e: RuntimeException) {
            false // e.g. IllegalArgumentException from a vendor's stricter JobScheduler
        }
    }

    /**
     * Runs one scan with every tier available right now and saves it as the new baseline. Notifies
     * every time while the user has notifications on, whatever the scan found. Call it off the main
     * thread.
     */
    suspend fun runScan(context: Context): ScheduledScanSummary {
        val app = context.applicationContext
        val settings = ScheduleSettings(app)
        val platform = SharedPlatform.acquire(app)
        try {
            platform.root.enabled = settings.rootEnabled
            awaitShizuku(platform)
            val checks = allChecks(platform)
            val results = SharedPlatform.scanLock.withLock {
                val scanContext = platform.newScanContext().copy(trustedApps = settings.trusted)
                try {
                    scanner.scan(checks, scanContext).toList()
                } finally {
                    // The root shell lives only as long as a scan, even a cancelled one.
                    withContext(NonCancellable) { platform.scanFinished() }
                }
            }
            val byId = results.associateBy { it.spec.id }
            val findings = checks.mapNotNull { byId[it.spec.id] }
            val muted = settings.muted
            val index = HardeningIndex.of(findings, muted)
            val now = System.currentTimeMillis()
            val snapshot = ScanSnapshot.of(findings, index.score, now)
            val previous = ScanHistory.record(app, snapshot)
            val changes = ScanChanges.between(previous, snapshot, muted)
            settings.recordRun(now, index.score, changes.newIssues.size)
            if (settings.notify) {
                ScanNotifier.show(
                    context = app,
                    findings = findings,
                    index = index,
                    changes = changes,
                    previousScore = previous?.score,
                    verbose = settings.verbose,
                )
            }
            return ScheduledScanSummary(index.score, changes.newIssues.size)
        } finally {
            SharedPlatform.release(platform)
        }
    }

    /**
     * Shizuku hands Droynis its binder shortly after the process starts, and a scheduled scan may
     * be what started it: wait a few seconds for it, but only while Shizuku is installed and not
     * yet reachable.
     */
    private suspend fun awaitShizuku(platform: AndroidPlatform) {
        repeat(SHIZUKU_WAIT_STEPS) {
            if (platform.shizuku.status().state != ShizukuState.NOT_RUNNING) return
            delay(SHIZUKU_WAIT_STEP)
        }
    }
}
