package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Tier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BaseChecksTest {

    private val specs = baseChecks(FakeProbes()).map { it.spec }

    @Test
    fun `ids and titles are unique`() {
        assertEquals(specs.size, specs.map { it.id }.toSet().size)
        assertEquals(specs.size, specs.map { it.title }.toSet().size)
    }

    @Test
    fun `every base check runs without extra privileges`() {
        assertTrue(specs.all { it.requiredTier == Tier.BASE && it.requires.isEmpty() })
    }

    @Test
    fun `every check explains itself and says what to do`() {
        for (spec in specs) {
            assertTrue(spec.explanation.isNotBlank(), spec.id)
            assertTrue(spec.remediation.text.isNotBlank(), spec.id)
        }
    }
}
