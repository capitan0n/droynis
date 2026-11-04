package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class StorageSpaceCheckTest {

    private suspend fun outcome(total: Long, free: Long) =
        StorageSpaceCheck(FakeStorage(value(StorageSpace(total, free)))).outcome()

    @Test
    fun `more than 80 percent in use fails`() = runTest {
        val full = outcome(128 * GB, 23_400_000_000)
        assertEquals(Status.FAIL, full.status)
        assertEquals("Storage is 82% full (23.4 GB free)", full.summary)
        assertEquals("82% used: 23.4 GB free of 128 GB", full.evidence.single().value)

        val roomy = outcome(128 * GB, 64 * GB)
        assertEquals(Status.PASS, roomy.status)
        assertEquals("Storage is 50% full (64.0 GB free)", roomy.summary)
    }

    @Test
    fun `exactly 80 percent passes and one byte more fails`() = runTest {
        assertEquals(Status.PASS, outcome(100 * GB, 20 * GB).status)
        assertEquals("Storage is 80% full (20.0 GB free)", outcome(100 * GB, 20 * GB).summary)

        assertEquals(Status.FAIL, outcome(100 * GB, 20 * GB - 1).status)

        val over = outcome(100 * GB, 19_900_000_000)
        assertEquals(Status.FAIL, over.status)
        assertEquals("Storage is 81% full (19.9 GB free)", over.summary)
    }

    @Test
    fun `a full or empty phone is judged too`() = runTest {
        assertEquals(Status.FAIL, outcome(32 * GB, 0).status)
        assertEquals("Storage is 100% full (0 MB free)", outcome(32 * GB, 0).summary)
        assertEquals(Status.PASS, outcome(32 * GB, 32 * GB).status)
        assertEquals("Storage is 0% full (32.0 GB free)", outcome(32 * GB, 32 * GB).summary)
    }

    @Test
    fun `numbers that can't be right are unknown, never passed`() = runTest {
        assertEquals(Status.UNKNOWN, outcome(0, 0).status)
        assertEquals(Status.UNKNOWN, outcome(-1, 0).status)
        assertEquals(Status.UNKNOWN, outcome(64 * GB, -1).status)
        assertEquals(Status.UNKNOWN, outcome(64 * GB, 65 * GB).status)
        assertEquals("0 of 0 bytes free", outcome(0, 0).evidence.single().value)
    }

    @Test
    fun `a storage reading that failed is unknown or unsupported`() = runTest {
        assertEquals(Status.UNKNOWN, StorageSpaceCheck(FakeStorage(unavailable())).status())
        assertEquals(Status.UNSUPPORTED, StorageSpaceCheck(FakeStorage(unsupported("no storage stats service"))).status())
    }

    @Test
    fun `used percent rounds up and sizes use decimal units`() {
        assertEquals(1, StorageSpaceCheck.usedPercent(StorageSpace(1000, 999)))
        assertEquals(100, StorageSpaceCheck.usedPercent(StorageSpace(1000, 1)))
        assertNull(StorageSpaceCheck.usedPercent(StorageSpace(0, 0)))
        // A 2 TB phone stays well inside Long while computing the percent.
        assertEquals(75, StorageSpaceCheck.usedPercent(StorageSpace(2_000 * GB, 500 * GB)))

        assertEquals("850 MB", StorageSpaceCheck.size(850_400_000))
        assertEquals("1.0 GB", StorageSpaceCheck.size(GB))
        assertEquals("99.9 GB", StorageSpaceCheck.size(99_940_000_000))
        assertEquals("256 GB", StorageSpaceCheck.size(256 * GB))
    }

    @Test
    fun `the fix opens Storage settings`() {
        val spec = StorageSpaceCheck(FakeStorage()).spec
        assertEquals(listOf(SettingsActions.INTERNAL_STORAGE), spec.remediation.settingsActions)
    }

    private companion object {
        const val GB = 1_000_000_000L
    }
}
