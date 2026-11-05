package io.github.capitan0n.droynis.schedule

import android.app.job.JobParameters
import android.app.job.JobService
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
            try {
                ScheduledScans.runScan(applicationContext)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Never crash in the background; the next period tries again.
                Log.w(TAG, "Scheduled scan failed", e)
            } finally {
                // After onStopJob the system has already ended the job.
                if (isActive) jobFinished(params, false)
            }
        }
        return true
    }

    /** The system stopped the job (constraints, quota): drop this run; the next period runs as usual. */
    override fun onStopJob(params: JobParameters): Boolean {
        scope.coroutineContext.cancelChildren()
        return false
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val TAG = "Droynis"
    }
}
