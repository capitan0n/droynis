package io.github.capitan0n.droynis.checks.base

import kotlin.test.Test
import kotlin.test.assertEquals

class SupportTest {

    @Test
    fun `switch states`() {
        assertEquals(SwitchState.ON, switchState("1"))
        assertEquals(SwitchState.ON, switchState(" 2 ", on = setOf("1", "2")))
        assertEquals(SwitchState.OFF, switchState("0"))
        assertEquals(SwitchState.UNSET, switchState(null))
        assertEquals(SwitchState.UNEXPECTED, switchState("on"))
    }

    @Test
    fun `names are joined like a sentence`() {
        assertEquals("", emptyList<String>().joinNames())
        assertEquals("Signal", listOf("Signal").joinNames())
        assertEquals("Signal and Tasker", listOf("Signal", "Tasker").joinNames())
        assertEquals("Signal, Tasker and 2 more", listOf("Signal", "Tasker", "A", "B").joinNames())
    }

    @Test
    fun `counts pluralize`() {
        assertEquals("1 app", count(1, "app"))
        assertEquals("3 apps", count(3, "app"))
        assertEquals("2 user CA certificates", count(2, "user CA certificate"))
    }
}
