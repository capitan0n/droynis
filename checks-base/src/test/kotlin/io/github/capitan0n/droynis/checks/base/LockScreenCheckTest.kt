package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class LockScreenCheckTest {

    @Test
    fun `a secure lock screen is a PASS`() = runTest {
        val outcome = LockScreenCheck(FakeKeyguard(value(true), value(PasswordComplexity.HIGH))).run(scanContext())

        assertEquals(Status.PASS, outcome.status)
        assertEquals("HIGH", outcome.evidence.single { it.label == "Lock complexity" }.value)
    }

    @Test
    fun `no lock screen is a FAIL`() = runTest {
        val outcome = LockScreenCheck(FakeKeyguard(value(false), value(PasswordComplexity.NONE))).run(scanContext())

        assertEquals(Status.FAIL, outcome.status)
    }

    @Test
    fun `an unreadable state is UNKNOWN`() = runTest {
        val outcome = LockScreenCheck(FakeKeyguard(unavailable("SecurityException"))).run(scanContext())

        assertEquals(Status.UNKNOWN, outcome.status)
    }

    @Test
    fun `a missing keyguard service is UNSUPPORTED`() = runTest {
        val outcome = LockScreenCheck(FakeKeyguard(unsupported("no KeyguardManager"))).run(scanContext())

        assertEquals(Status.UNSUPPORTED, outcome.status)
    }

    @Test
    fun `complexity is optional evidence and does not change the verdict`() = runTest {
        val outcome = LockScreenCheck(FakeKeyguard(value(true), unsupported("needs API 29"))).run(scanContext())

        assertEquals(Status.PASS, outcome.status)
        val complexity = outcome.evidence.single { it.label == "Lock complexity" }
        assertNull(complexity.value)
        assertEquals("not supported: needs API 29", complexity.note)
    }
}
