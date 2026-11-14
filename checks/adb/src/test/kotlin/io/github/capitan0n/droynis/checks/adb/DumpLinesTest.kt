package io.github.capitan0n.droynis.checks.adb

import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class DumpLinesTest {

    @Test
    fun `lines lose trailing space, and a line longer than any record is cut and marked`() {
        val lines = dumpLines("  short \t\n" + "x".repeat(MAX_LINE + 10) + "\r\nlast")

        assertEquals("  short", lines[0])
        assertEquals("x".repeat(MAX_LINE) + "…", lines[1])
        assertEquals("last", lines[2])
    }

    @Test
    fun `a prefix counts after spaces and tabs only`() {
        assertTrue("Uid u0a1:".startsAfterIndent("Uid "))
        assertTrue(" \t  Uid u0a1:".startsAfterIndent("Uid "))
        assertFalse("  x Uid u0a1:".startsAfterIndent("Uid "))
        assertFalse("    ".startsAfterIndent("Uid "))
    }

    @Test
    fun `a dump is parsed once while it is the same string`() {
        var parses = 0
        val last = LastParse { text: String -> parses++; text.length }
        val dump = "a".repeat(10)

        repeat(3) { assertEquals(10, last.of(dump)) }
        assertEquals(1, parses)

        // Equal text from another read is another dump.
        last.of(String(dump.toCharArray()))
        assertEquals(2, parses)
    }

    @Test
    fun `checks reading one dump at the same time wait for a single parse`() {
        val parses = AtomicInteger()
        val last = LastParse { text: String ->
            parses.incrementAndGet()
            Thread.sleep(50)
            text.length
        }
        val dump = "a".repeat(10)
        val start = CountDownLatch(1)
        val checks = List(8) { thread { start.await(); last.of(dump) } }

        start.countDown()
        checks.forEach { it.join() }
        assertEquals(1, parses.get())
    }
}
