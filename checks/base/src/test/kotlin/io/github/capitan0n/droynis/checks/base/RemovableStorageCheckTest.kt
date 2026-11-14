package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

/** Unencrypted SD card or USB drive (INTG-1091). */
class RemovableStorageCheckTest {

    private fun check(vararg volumes: RemovableVolume) = RemovableStorageCheck(FakeStorage(removable = value(volumes.toList())))

    @Test
    fun `a base check that opens Storage`() {
        val spec = check().spec
        assertEquals("INTG-1091", spec.id)
        assertEquals(Tier.BASE, spec.requiredTier)
        assertEquals(listOf(SettingsActions.INTERNAL_STORAGE), spec.remediation.settingsActions)
    }

    @Test
    fun `no SD card or USB drive passes`() = runTest {
        val outcome = check().outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No SD card or USB drive is in use as portable storage", outcome.summary)
        assertEquals("none", outcome.evidence.single().value)
    }

    @Test
    fun `a mounted portable card fails, read-only too`() = runTest {
        val outcome = check(
            RemovableVolume("SanDisk SD card", RemovableVolume.MOUNTED),
            RemovableVolume("USB drive", RemovableVolume.MOUNTED_READ_ONLY),
        ).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 SD cards or USB drives are in use without encryption: SanDisk SD card and USB drive", outcome.summary)
        assertEquals(listOf("mounted, not encrypted", "mounted read-only, not encrypted"), outcome.evidence.map { it.note })
    }

    @Test
    fun `a card that isn't mounted is listed but passes`() = runTest {
        val outcome = check(RemovableVolume("SD card", "unmounted")).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No portable SD card or USB drive is mounted", outcome.summary)
        assertEquals("not mounted (unmounted)", outcome.evidence.single().note)
    }

    @Test
    fun `a list that can't be read is never a pass`() = runTest {
        val outcome = RemovableStorageCheck(FakeStorage(removable = unavailable("storage service died"))).outcome()

        assertEquals(Status.UNKNOWN, outcome.status)
    }
}
