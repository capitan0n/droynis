package io.github.capitan0n.droynis.schedule

import android.app.job.JobParameters
import android.app.job.JobService
import android.os.Build
import android.util.Log
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Runs the periodic scan JobScheduler starts. Only the system can bind it (BIND_JOB_SERVICE). */
class ScheduledScanService : JobService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onStartJob(params: JobParameters): Boolean {
        scope.launch {
            val startedAt = System.currentTimeMillis()
            try {
                ScheduledScans.runScan(applicationContext)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Never crash in the background; the next period tries again.
                Log.w(TAG, "Scheduled scan failed", e)
            } finally {
                // After onStopJob the system has already ended the job, and its retry is this
                // period's run: only a run that wasn't stopped counts for timing.
                if (isActive) {
                    ScheduleSettings(applicationContext).recordJobRun(startedAt)
                    jobFinished(params, false)
                }
            }
        }
        return true
    }

    /**
     * The system stopped the job (Doze, quota, battery low): the scan is dropped, and JobScheduler
     * tries again with backoff rather than waiting a full period.
     */
    override fun onStopJob(params: JobParameters): Boolean {
        scope.coroutineContext.cancelChildren()
        return retryAfterStop(params)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    /**
     * Retry unless the scan used up its time, when it would likely do so again, or the user stopped
     * Droynis. Android 12+ says why it stopped the job; before that, always retry.
     */
    private fun retryAfterStop(params: JobParameters): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        return when (params.stopReason) {
            JobParameters.STOP_REASON_TIMEOUT, JobParameters.STOP_REASON_USER -> false
            else -> true
        }
    }

    private companion object {
        const val TAG = "Droynis"
    }
}
