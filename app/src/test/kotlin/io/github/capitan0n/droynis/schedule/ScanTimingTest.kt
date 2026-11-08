package io.github.capitan0n.droynis.schedule

import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanTimingTest {

    @Test
    fun lateMeansPastAndroidsWindowAndDoze() {
        assertEquals(33.hours, ScanInterval.DAILY.lateAfter)
        assertEquals(7.days + 18.hours, ScanInterval.WEEKLY.lateAfter)
    }

    @Test
    fun androidsOwnWindowIsNeverLate() {
        for (interval in ScanInterval.entries - ScanInterval.OFF) {
            val start = 1_700_000_000_000
            val dueBy = start + interval.lateAfter.inWholeMilliseconds
            val endOfWindow = start + (interval.period + interval.flex).inWholeMilliseconds
            assertFalse(interval.name, ScheduleSettings.ranLate(endOfWindow, dueBy))
            assertFalse(interval.name, ScheduleSettings.ranLate(dueBy, dueBy))
            assertTrue(interval.name, ScheduleSettings.ranLate(dueBy + 1, dueBy))
        }
    }

    @Test
    fun noDueTimeIsNotLate() {
        // A job scheduled before Droynis timed its runs.
        assertFalse(ScheduleSettings.ranLate(Long.MAX_VALUE, null))
    }
}
