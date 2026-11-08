package io.github.capitan0n.droynis

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WhatsNewTest {

    private val notes = "Scheduled scans."

    @Test
    fun notOnAFreshInstall() {
        assertFalse(WhatsNew.shouldShow(notes, current = 23, seen = null, updated = false))
    }

    @Test
    fun onceAfterAnUpdate() {
        // From a version before the dialog, which kept no version.
        assertTrue(WhatsNew.shouldShow(notes, current = 23, seen = null, updated = true))
        assertTrue(WhatsNew.shouldShow(notes, current = 24, seen = 23, updated = true))
        assertFalse(WhatsNew.shouldShow(notes, current = 23, seen = 23, updated = true))
    }

    @Test
    fun notAfterADowngradeOrWithoutNotes() {
        assertFalse(WhatsNew.shouldShow(notes, current = 23, seen = 24, updated = true))
        assertFalse(WhatsNew.shouldShow(" \n", current = 24, seen = 23, updated = true))
    }

    /** The build reads the changelog into BuildConfig; this checks it arrives unchanged, quotes and all. */
    @Test
    fun builtInNotesAreThisVersionsChangelog() {
        val changelog = File("../fastlane/metadata/android/en-US/changelogs/${BuildConfig.VERSION_CODE}.txt")
        assertTrue("Write $changelog for this version", changelog.isFile)
        val text = changelog.readText().trim()
        assertEquals(text, BuildConfig.WHATS_NEW)
        assertTrue("F-Droid allows 500 characters, not ${text.length}", text.length <= 500)
    }
}
