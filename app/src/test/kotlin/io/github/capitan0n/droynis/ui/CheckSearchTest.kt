package io.github.capitan0n.droynis.ui

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CheckSearchTest {

    private val sms = CheckSpec(
        id = "APPS-4008",
        category = Category.APPS,
        title = "Apps that can read your SMS or call log",
        severity = Severity.NOTICE,
        explanation = "One-time login codes arrive by SMS.",
        remediation = Remediation("Remove the permission under Settings › Apps."),
    )

    private val lock = CheckSpec(
        id = "ACCS-2007",
        category = Category.ACCESS_CONTROL,
        title = "Screen lock strength",
        severity = Severity.NOTICE,
        explanation = "A pattern or a simple PIN is quick to guess when keeping the phone in sight.",
        remediation = Remediation("Set a longer PIN or a password over Wi-Fi or not."),
    )

    private fun matches(query: String, spec: CheckSpec, finding: Finding? = null) =
        matchesSearch(searchText(spec, finding), searchWords(query))

    @Test
    fun `any case, every word, and each at the start of a word`() {
        assertTrue(matches("sms", sms))
        assertTrue(matches("SMS call", sms))
        assertFalse(matches("sms password", sms))
        // "pin" is in "keeping" too, but only the word PIN counts.
        assertTrue(matches("pin", lock))
        assertFalse(matches("eping", lock))
        assertTrue(matches("strength", lock))
    }

    @Test
    fun `ids, categories and hyphenated words are found`() {
        assertTrue(matches("4008", sms))
        assertTrue(matches("apps-4008", sms))
        assertTrue(matches("access control", lock))
        assertTrue(matches("wifi", lock))
        assertTrue(matches("wi-fi", lock))
    }

    @Test
    fun `what a scan found is searched too`() {
        val finding = Finding(
            spec = sms,
            status = Status.FAIL,
            severity = Severity.WARNING,
            summary = "1 app can read your SMS or call log: Sideloaded Game",
            evidence = listOf(Evidence("Can read your SMS", "com.example.game", Source("PackageManager"), "installed from outside an app store")),
            elapsedMillis = 3,
        )
        assertFalse(matches("sideloaded", sms))
        assertTrue(matches("sideloaded game", sms, finding))
        assertTrue(matches("com.example", sms, finding))
        assertTrue(matches("outside", sms, finding))
    }

    @Test
    fun `a blank query matches everything`() {
        assertEquals(emptyList<String>(), searchWords("  \t "))
        assertTrue(matches("", lock))
    }
}
