package io.github.capitan0n.droynis.schedule

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanSnapshotTest {

    private fun snapshot(vararg checks: Pair<String, CheckState>, score: Int? = 80) =
        ScanSnapshot(takenAt = 1_700_000_000_000, score = score, checks = linkedMapOf(*checks))

    private val pass = CheckState(Status.PASS, Severity.WARNING)
    private val failWarning = CheckState(Status.FAIL, Severity.WARNING)
    private val failCritical = CheckState(Status.FAIL, Severity.CRITICAL)
    private val failNotice = CheckState(Status.FAIL, Severity.NOTICE)
    private val unknown = CheckState(Status.UNKNOWN, Severity.WARNING)
    private val unsupported = CheckState(Status.UNSUPPORTED, Severity.WARNING)

    @Test
    fun encodesAndDecodesTheSameSnapshot() {
        val original = snapshot("ACCS-2001" to pass, "INTG-1001" to failCritical, "SUSP-5102" to unsupported)
        assertEquals(original, ScanSnapshot.decode(original.encode()))
    }

    @Test
    fun keepsAMissingScore() {
        val original = snapshot("ACCS-2001" to unknown, score = null)
        assertEquals(original, ScanSnapshot.decode(original.encode()))
    }

    @Test
    fun rejectsTextItCannotRead() {
        assertNull(ScanSnapshot.decode(""))
        assertNull(ScanSnapshot.decode("something else\ntime 1\n"))
        assertNull(ScanSnapshot.decode("droynis-snapshot 1\nscore 80\n")) // no time
    }

    @Test
    fun skipsLinesWithUnknownValues() {
        val text = "droynis-snapshot 1\ntime 5\nscore 70\nACCS-2001 PASS WARNING\nACCS-2002 MAYBE WARNING\n"
        assertEquals(snapshot("ACCS-2001" to pass, score = 70).copy(takenAt = 5), ScanSnapshot.decode(text))
    }

    @Test
    fun readsAMovedCheckUnderItsNewId() {
        val text = "droynis-snapshot 1\ntime 5\nscore 70\nAPPS-4101 PASS WARNING\n"
        assertEquals(setOf("SUSP-5102"), ScanSnapshot.decode(text)?.checks?.keys)
    }

    @Test
    fun aCheckThatPassedAndNowFailsIsNew() {
        val changes = ScanChanges.between(snapshot("A" to pass), snapshot("A" to failWarning), emptySet())
        assertEquals(listOf("A"), changes.newIssues)
        assertTrue(changes.worse)
    }

    @Test
    fun aFailureThatGotMoreSevereIsNew() {
        val changes = ScanChanges.between(snapshot("A" to failWarning), snapshot("A" to failCritical), emptySet())
        assertEquals(listOf("A"), changes.newIssues)
    }

    @Test
    fun aFailureThatStaysOrEasesIsNotNew() {
        val same = ScanChanges.between(snapshot("A" to failWarning), snapshot("A" to failWarning), emptySet())
        val eased = ScanChanges.between(snapshot("A" to failWarning), snapshot("A" to failNotice), emptySet())
        assertFalse(same.worse)
        assertFalse(eased.worse)
    }

    @Test
    fun newIssuesComeMostSevereFirst() {
        val changes = ScanChanges.between(
            snapshot("A" to pass, "B" to pass, "C" to pass),
            snapshot("A" to failNotice, "B" to failCritical, "C" to failWarning),
            emptySet(),
        )
        assertEquals(listOf("B", "C", "A"), changes.newIssues)
    }

    @Test
    fun aFailureThatNowPassesIsFixed() {
        val changes = ScanChanges.between(snapshot("A" to failWarning), snapshot("A" to pass), emptySet())
        assertEquals(listOf("A"), changes.fixed)
        assertFalse(changes.worse)
    }

    @Test
    fun aCheckThatCouldNotRunIsNeitherNewNorFixed() {
        val changes = ScanChanges.between(snapshot("A" to pass, "B" to failWarning), snapshot("A" to unsupported, "B" to unknown), emptySet())
        assertEquals(listOf("A", "B"), changes.notRun)
        assertTrue(changes.newIssues.isEmpty())
        assertTrue(changes.fixed.isEmpty())
    }

    @Test
    fun aFailureWithNothingToCompareToIsNotNew() {
        val unscoredBefore = ScanChanges.between(snapshot("A" to unknown), snapshot("A" to failCritical), emptySet())
        val newCheck = ScanChanges.between(snapshot(), snapshot("A" to failCritical), emptySet())
        assertFalse(unscoredBefore.worse)
        assertFalse(newCheck.worse)
    }

    @Test
    fun mutedChecksAreLeftOut() {
        val changes = ScanChanges.between(snapshot("A" to pass), snapshot("A" to failCritical), setOf("A"))
        assertEquals(ScanChanges.NONE, changes)
    }

    @Test
    fun noPreviousScanMeansNoChanges() {
        assertEquals(ScanChanges.NONE, ScanChanges.between(null, snapshot("A" to failCritical), emptySet()))
    }

    @Test
    fun aCheckThatCouldNotRunKeepsItsLastResult() {
        val before = snapshot("A" to failWarning, "B" to pass, "C" to pass)
        val now = snapshot("A" to unsupported, "B" to unknown, "C" to failWarning)
        val merged = now.carryingOver(before)
        assertEquals(snapshot("A" to failWarning, "B" to pass, "C" to failWarning), merged)
    }

    @Test
    fun carryingOverDropsChecksThatNoLongerExist() {
        val merged = snapshot("A" to pass).carryingOver(snapshot("A" to pass, "OLD" to failWarning))
        assertEquals(setOf("A"), merged.checks.keys)
    }

    @Test
    fun aRegressionIsCaughtAfterAScanWithoutItsTier() {
        // Shizuku ran, then did not, then ran again and the check now fails.
        val first = snapshot("A" to pass)
        val second = snapshot("A" to unsupported).carryingOver(first)
        val third = snapshot("A" to failWarning)
        assertEquals(listOf("A"), ScanChanges.between(second, third, emptySet()).newIssues)
    }
}
