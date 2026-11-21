package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class StalkerwareCheckTest {
    @Test
    fun `the registered check reports that it is inactive`() = runTest {
        val check = baseChecks(FakeProbes()).single { it.spec.id == "SUSP-5007" }
        val result = check.outcome()

        assertEquals(Status.UNSUPPORTED, result.status)
        assertEquals("Currently not running by design.", result.summary)
        assertTrue(result.evidence.isEmpty())
    }
}
