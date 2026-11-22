package io.github.capitan0n.droynis.checks.base

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** The privileged usage reader's output, which SUSP-5003 reads with Shizuku or root. */
class UsageDumpTest {

    @Test
    fun `lines written by the reader are read back`() {
        val use = ScreenUse("com.example.ads", 3, Instant.ofEpochMilli(1_794_000_000_000))
        val text = "WARNING: linker noise\n${UsageDump.HEADER}\n${UsageDump.line(use)}\napp=org.other times=1 last=5\n"

        val parsed = assertIs<UsageDump.Result.Parsed>(UsageDump.parse(text))
        assertEquals(use, parsed.screens["com.example.ads"])
        assertEquals(setOf("com.example.ads", "org.other"), parsed.screens.keys)
        // No app showed a screen: an empty history, read.
        assertTrue(assertIs<UsageDump.Result.Parsed>(UsageDump.parse(UsageDump.HEADER)).screens.isEmpty())
    }

    @Test
    fun `an error, a missing header or an odd line fails the read`() {
        val failed = assertIs<UsageDump.Result.Failed>(UsageDump.parse("${UsageDump.HEADER}\nerror=SecurityException: denied"))
        assertEquals("SecurityException: denied", failed.reason)
        assertEquals("the reader printed nothing", assertIs<UsageDump.Result.Failed>(UsageDump.parse("")).reason)
        assertIs<UsageDump.Result.Failed>(UsageDump.parse("app=com.example times=1 last=5"))
        assertIs<UsageDump.Result.Failed>(UsageDump.parse("${UsageDump.HEADER}\napp=com.example times=many last=5"))
        assertIs<UsageDump.Result.Failed>(UsageDump.parse("${UsageDump.HEADER}\napp=com.example times=99999999999 last=5"))
    }
}
