package io.github.capitan0n.droynis.core

import java.time.ZonedDateTime
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.TimeSource
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** Scan-wide facts, fixed when the scan starts so every check sees the same "now". */
data class ScanContext(
    val startedAt: ZonedDateTime,
    val sdkInt: Int,
    val capabilities: Capabilities = Capabilities(),
    /** Droynis' own package, so a check can tell the auditor's own entries apart. */
    val appPackage: String? = null,
    /** Droynis' own uid, for lists that name apps by uid. */
    val appUid: Int? = null,
)

/**
 * Runs checks concurrently and isolates them: a check that throws or exceeds its timeout yields
 * UNKNOWN instead of failing the scan.
 *
 * Limits of in-process isolation: a blocking binder call cannot be interrupted, so a timed-out
 * check keeps its worker thread until the call returns (the scan does not wait for it). Native
 * crashes and out-of-memory kills still take the process down.
 */
class Scanner(private val workDispatcher: CoroutineDispatcher = Dispatchers.IO) {

    // Checks run outside the caller's scope so a hung check cannot hold the scan open.
    private val isolation = CoroutineScope(SupervisorJob() + workDispatcher)

    /**
     * Emits one [Finding] per check, in completion order. Starting, gating and timing the checks
     * runs on the work dispatcher whatever thread collects: on Android's main thread, a busy frame
     * would otherwise hold back every result and count its wait as the check's time.
     */
    fun scan(checks: List<Check>, context: ScanContext): Flow<Finding> = channelFlow {
        for (check in checks) {
            launch { send(execute(check, context)) }
        }
    }.flowOn(workDispatcher)

    private suspend fun execute(check: Check, context: ScanContext): Finding {
        val spec = check.spec
        val start = TimeSource.Monotonic.markNow()
        val outcome = gate(spec, context) ?: runIsolated(check, context)
        return Finding(
            spec = spec,
            status = outcome.status,
            severity = maxOf(spec.severity, outcome.escalation ?: spec.severity),
            summary = outcome.summary,
            evidence = outcome.evidence,
            elapsedMillis = start.elapsedNow().inWholeMilliseconds,
        )
    }

    private fun gate(spec: CheckSpec, context: ScanContext): Outcome? {
        if (context.sdkInt < spec.minSdk) {
            return Outcome.unsupported("Needs Android API ${spec.minSdk}; this device runs API ${context.sdkInt}")
        }
        val missing = context.capabilities.missingFor(spec)
        if (missing.isNotEmpty()) {
            return Outcome.unsupported("Needs ${missing.joinToString()} (${spec.requiredTier} tier)")
        }
        return null
    }

    private suspend fun runIsolated(check: Check, context: ScanContext): Outcome {
        val timeout = check.spec.timeout
        val work = isolation.async { check.run(context) }
        return try {
            withTimeoutOrNull(timeout) { work.await() }
                ?: Outcome.unknown("Timed out after $timeout").also { work.cancel() }
        } catch (e: CancellationException) {
            work.cancel()
            currentCoroutineContext().ensureActive() // the scan itself was cancelled: propagate
            Outcome.unknown("Check was cancelled: ${e.describe()}")
        } catch (t: Throwable) {
            // Deliberately broad: NoSuchMethodError from an OEM framework is as likely as a SecurityException.
            Outcome.unknown("Check failed: ${t.describe()}")
        }
    }

    private fun Throwable.describe(): String =
        "${this::class.java.simpleName}: ${message.orEmpty()}".take(MAX_ERROR_LENGTH)

    private companion object {
        const val MAX_ERROR_LENGTH = 200
    }
}
