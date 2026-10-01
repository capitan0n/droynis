package io.github.capitan0n.droynis.core

import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest

class ScannerTest {

    private val context = ScanContext(
        startedAt = ZonedDateTime.of(2026, 10, 1, 12, 0, 0, 0, ZoneOffset.UTC),
        sdkInt = 37,
    )

    @Test
    fun `passes the outcome through with the spec severity`() = runTest {
        val check = FakeCheck(spec(severity = Severity.WARNING)) {
            Outcome.fail("broken", listOf(Evidence("key", "1", Source("fake"))))
        }

        val finding = scanner().scanOne(check)

        assertEquals(Status.FAIL, finding.status)
        assertEquals(Severity.WARNING, finding.severity)
        assertEquals("broken", finding.summary)
        assertEquals(listOf(Evidence("key", "1", Source("fake"))), finding.evidence)
    }

    @Test
    fun `a FAIL can escalate severity but never lower it`() = runTest {
        val escalated = FakeCheck(spec("TEST-0001", Severity.WARNING)) {
            Outcome.fail("very old", escalation = Severity.CRITICAL)
        }
        val lowered = FakeCheck(spec("TEST-0002", Severity.WARNING)) {
            Outcome.fail("minor", escalation = Severity.NOTICE)
        }

        val findings = scanner().scan(listOf(escalated, lowered), context).toList().associateBy { it.spec.id }

        assertEquals(Severity.CRITICAL, findings.getValue("TEST-0001").severity)
        assertEquals(Severity.WARNING, findings.getValue("TEST-0002").severity)
    }

    @Test
    fun `only a FAIL may escalate`() {
        assertFailsWith<IllegalArgumentException> { Outcome(Status.PASS, "fine", escalation = Severity.CRITICAL) }
    }

    @Test
    fun `a throwing check becomes UNKNOWN without affecting the others`() = runTest {
        val crashing = FakeCheck(spec("TEST-0001")) { throw SecurityException("denied by OEM") }
        val linkage = FakeCheck(spec("TEST-0002")) { throw NoSuchMethodError("isDeviceSecure") }
        val healthy = FakeCheck(spec("TEST-0003")) { Outcome.pass("fine") }

        val findings = scanner().scan(listOf(crashing, linkage, healthy), context).toList().associateBy { it.spec.id }

        assertEquals(Status.UNKNOWN, findings.getValue("TEST-0001").status)
        assertTrue("SecurityException" in findings.getValue("TEST-0001").summary)
        assertEquals(Status.UNKNOWN, findings.getValue("TEST-0002").status)
        assertTrue("NoSuchMethodError" in findings.getValue("TEST-0002").summary)
        assertEquals(Status.PASS, findings.getValue("TEST-0003").status)
    }

    @Test
    fun `a check exceeding its timeout becomes UNKNOWN`() = runTest {
        val hanging = FakeCheck(spec(timeout = 2.seconds)) {
            delay(1.hours)
            Outcome.pass("too late")
        }

        val finding = scanner().scanOne(hanging)

        assertEquals(Status.UNKNOWN, finding.status)
        assertTrue("Timed out" in finding.summary)
    }

    @Test
    fun `a blocked thread does not hold the scan open`(): Unit = runBlocking {
        val release = CountDownLatch(1)
        val blocked = FakeCheck(spec("TEST-0001", timeout = 200.milliseconds)) {
            release.await() // like a binder call that never returns; not interruptible
            Outcome.pass("too late")
        }
        val healthy = FakeCheck(spec("TEST-0002")) { Outcome.pass("fine") }

        try {
            val findings = Scanner().scan(listOf(blocked, healthy), context).toList().associateBy { it.spec.id }

            assertEquals(Status.UNKNOWN, findings.getValue("TEST-0001").status)
            assertEquals(Status.PASS, findings.getValue("TEST-0002").status)
        } finally {
            release.countDown()
        }
    }

    @Test
    fun `a check that cancels itself becomes UNKNOWN`() = runTest {
        val check = FakeCheck(spec()) { throw kotlinx.coroutines.CancellationException("gave up") }

        val finding = scanner().scanOne(check)

        assertEquals(Status.UNKNOWN, finding.status)
    }

    @Test
    fun `cancelling the scan cancels running checks instead of reporting them`() = runTest {
        val started = CompletableDeferred<Unit>()
        val cancelled = AtomicBoolean(false)
        val check = FakeCheck(spec(timeout = 1.hours)) {
            started.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                cancelled.set(true)
            }
        }
        val emitted = mutableListOf<Finding>()

        val job = launch { scanner().scan(listOf(check), context).toList(emitted) }
        started.await()
        job.cancelAndJoin()
        testScheduler.advanceUntilIdle()

        assertTrue(job.isCancelled)
        assertTrue(cancelled.get())
        assertTrue(emitted.isEmpty())
    }

    @Test
    fun `checks above the device SDK are UNSUPPORTED and never run`() = runTest {
        val check = FakeCheck(spec(minSdk = 36)) { Outcome.pass("fine") }

        val finding = scanner().scanOne(check, context.copy(sdkInt = 30))

        assertEquals(Status.UNSUPPORTED, finding.status)
        assertEquals(0, check.runs.get())
    }

    @Test
    fun `checks needing a missing grant are UNSUPPORTED and never run`() = runTest {
        val check = FakeCheck(spec(requires = setOf(Grant.DUMP))) { Outcome.pass("fine") }

        val finding = scanner().scanOne(check)

        assertEquals(Status.UNSUPPORTED, finding.status)
        assertTrue("DUMP" in finding.summary)
        assertEquals(0, check.runs.get())
    }

    @Test
    fun `checks run when their grant is held`() = runTest {
        val check = FakeCheck(spec(requires = setOf(Grant.DUMP))) { Outcome.pass("fine") }

        val finding = scanner().scanOne(check, context.copy(capabilities = Capabilities(setOf(Grant.DUMP))))

        assertEquals(Status.PASS, finding.status)
        assertEquals(1, check.runs.get())
    }

    // Checks and timeouts share the test scheduler, so delays run in virtual time.
    private fun TestScope.scanner() = Scanner(StandardTestDispatcher(testScheduler))

    private suspend fun Scanner.scanOne(check: Check, scanContext: ScanContext = context): Finding =
        scan(listOf(check), scanContext).toList().single()

    private fun spec(
        id: String = "TEST-0001",
        severity: Severity = Severity.WARNING,
        minSdk: Int = CheckSpec.MIN_SDK,
        requires: Set<Grant> = emptySet(),
        timeout: Duration = 5.seconds,
    ) = CheckSpec(
        id = id,
        category = Category.ACCESS_CONTROL,
        title = "Test check",
        severity = severity,
        explanation = "Why it matters.",
        remediation = Remediation("Fix it."),
        minSdk = minSdk,
        requires = requires,
        timeout = timeout,
    )

    private class FakeCheck(
        override val spec: CheckSpec,
        private val body: suspend (ScanContext) -> Outcome,
    ) : Check {
        val runs = AtomicInteger()

        override suspend fun run(context: ScanContext): Outcome {
            runs.incrementAndGet()
            return body(context)
        }
    }
}
