package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

/** Google Play system update (INTG-1012). Scans run on 2026-10-01. */
class PlaySystemUpdateCheckTest {

    private fun google(version: String) = value(ModuleMetadata(PlaySystemUpdateCheck.GOOGLE_PROVIDER, version))

    private suspend fun outcome(metadata: io.github.capitan0n.droynis.core.Reading<ModuleMetadata?>) =
        PlaySystemUpdateCheck(FakeModules(metadata)).run(scanContext())

    @Test
    fun `needs Android 10 and no privilege`() {
        val spec = PlaySystemUpdateCheck(FakeModules()).spec
        assertEquals(29, spec.minSdk)
        assertEquals(emptySet(), spec.requires)
    }

    @Test
    fun `an update up to 180 days old passes`() = runTest {
        val recent = outcome(google("2026-09-01"))
        assertEquals(Status.PASS, recent.status)
        assertEquals("Google Play system update 2026-09-01 is 30 days old", recent.summary)

        // 2026-04-04 is exactly 180 days before the scan.
        assertEquals(Status.PASS, outcome(google("2026-04-04")).status)
        assertEquals("Google Play system update 2026-10-01 is current", outcome(google("2026-10-01")).summary)
    }

    @Test
    fun `an older update fails, and one over a year old is a warning`() = runTest {
        val stale = outcome(google("2026-04-03"))
        assertEquals(Status.FAIL, stale.status)
        assertNull(stale.escalation)
        assertEquals("Google Play system update 2026-04-03 is 181 days old", stale.summary)

        // 2025-10-01 is exactly 365 days before the scan.
        assertNull(outcome(google("2025-10-01")).escalation)
        val old = outcome(google("2025-09-30"))
        assertEquals(Status.FAIL, old.status)
        assertEquals(Severity.WARNING, old.escalation)
    }

    @Test
    fun `a phone without Google's modules is not applicable, never passed`() = runTest {
        val none = outcome(value(null))
        assertEquals(Status.UNSUPPORTED, none.status)

        // AOSP's placeholder package has a plain version name.
        val aosp = outcome(value(ModuleMetadata("com.android.modulemetadata", "36")))
        assertEquals(Status.UNSUPPORTED, aosp.status)
        assertEquals("This Android build doesn't get Google Play system updates", aosp.summary)
    }

    @Test
    fun `a version that is no date, a date far ahead and an unreadable package are unknown`() = runTest {
        assertEquals(Status.UNKNOWN, outcome(google("14")).status)
        assertEquals(Status.UNKNOWN, outcome(google("2027-03-01")).status)
        assertEquals(Status.UNKNOWN, outcome(unavailable("access denied")).status)
        assertEquals(Status.UNSUPPORTED, outcome(unsupported("needs Android 10")).status)
    }
}
