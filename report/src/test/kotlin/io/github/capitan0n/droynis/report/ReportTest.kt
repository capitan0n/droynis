package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReportTest {

    private val context = ScanContext(ZonedDateTime.of(2026, 10, 1, 14, 2, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    @Test
    fun `verdicts follow status and severity`() {
        assertEquals(Verdict.PASSED, finding(Status.PASS, Severity.CRITICAL).verdict)
        assertEquals(Verdict.CRITICAL, finding(Status.FAIL, Severity.CRITICAL).verdict)
        assertEquals(Verdict.ATTENTION, finding(Status.FAIL, Severity.WARNING).verdict)
        assertEquals(Verdict.ATTENTION, finding(Status.FAIL, Severity.INFO).verdict)
        assertEquals(Verdict.UNKNOWN, finding(Status.UNKNOWN).verdict)
        assertEquals(Verdict.NOT_AVAILABLE, finding(Status.UNSUPPORTED).verdict)
    }

    @Test
    fun `verdict counts include every verdict`() {
        val counts = listOf(finding(Status.PASS), finding(Status.PASS), finding(Status.UNKNOWN)).countByVerdict()

        assertEquals(2, counts[Verdict.PASSED])
        assertEquals(1, counts[Verdict.UNKNOWN])
        assertEquals(0, counts[Verdict.CRITICAL])
    }

    @Test
    fun `grades`() {
        assertEquals(Grade.A, Grade.of(100))
        assertEquals(Grade.A, Grade.of(90))
        assertEquals(Grade.B, Grade.of(89))
        assertEquals(Grade.C, Grade.of(60))
        assertEquals(Grade.D, Grade.of(40)) // the critical cap lands here
        assertEquals(Grade.F, Grade.of(39))
        assertEquals(Grade.F, Grade.of(0))
    }

    @Test
    fun `markdown report lists the score, device facts and every finding`() {
        val findings = listOf(
            finding(Status.FAIL, Severity.WARNING, id = "ACCS-2011", title = "USB debugging", summary = "USB debugging is enabled"),
            finding(Status.PASS, Severity.CRITICAL, id = "ACCS-2001", title = "Secure lock screen", summary = "A PIN is set"),
        )

        val markdown = MarkdownReport.render(
            context,
            findings,
            HardeningIndex.of(findings),
            facts = listOf(DeviceFact("model", "Model", "FP6 | test")),
            appVersion = "0.2.0",
        )

        assertTrue(markdown.startsWith("# Droynis security report\n"))
        assertTrue("- Scanned: 2026-10-01 14:02 Z" in markdown)
        assertTrue("- Hardening index: 66 / 100 (grade C, fair)" in markdown)
        assertTrue("| Model | FP6 \\| test |" in markdown)
        assertTrue("### – USB debugging (ACCS-2011)" in markdown)
        assertTrue("**Needs attention**, severity warning: USB debugging is enabled" in markdown)
        assertTrue("- What to do: Fix it." in markdown)
        assertTrue("### ✓ Secure lock screen (ACCS-2001)" in markdown)
        assertTrue("- adb_enabled: `1`, via Settings.Global \"adb_enabled\"" in markdown)
        assertTrue(markdown.endsWith("\n") && !markdown.endsWith("\n\n"))
    }

    @Test
    fun `a capped score also shows the score without the cap`() {
        val findings = listOf(
            finding(Status.FAIL, Severity.CRITICAL, id = "INTG-1040"),
            finding(Status.PASS, Severity.CRITICAL, id = "ACCS-2001"),
        )

        val markdown = MarkdownReport.render(context, findings, HardeningIndex.of(findings), emptyList(), "0.4.0")

        assertTrue("- Hardening index: 40 / 100 (grade D, weak), capped by INTG-1040 (50 without the cap)" in markdown)
    }

    @Test
    fun `a report without a score says so`() {
        val markdown = MarkdownReport.render(context, emptyList(), HardeningIndex.of(emptyList()), emptyList(), "0.2.0")

        assertTrue("not available (no check could be scored)" in markdown)
    }

    @Test
    fun `category summaries count verdicts and find the worst`() {
        val findings = listOf(
            finding(Status.PASS),
            finding(Status.FAIL, Severity.NOTICE),
            finding(Status.UNKNOWN),
            finding(Status.PASS, category = Category.NETWORK),
        )
        val pending = finding(Status.PASS, category = Category.NETWORK).spec // not run yet

        val (access, network) = categorySummaries(findings.map { it.spec } + pending, findings)

        assertEquals(Category.ACCESS_CONTROL, access.category)
        assertEquals(3, access.total)
        assertEquals(2, access.scored)
        assertEquals(1, access.passed)
        assertEquals(1, access.issues)
        assertEquals(Verdict.ATTENTION, access.worst)
        assertEquals(2, network.total)
        assertEquals(Verdict.PASSED, network.worst)

        val unknownOnly = listOf(finding(Status.UNKNOWN))
        assertEquals(null, categorySummaries(unknownOnly.map { it.spec }, unknownOnly).single().worst)
    }

    @Test
    fun `issues are the failures, worst first, otherwise in order`() {
        val findings = listOf(
            finding(Status.FAIL, Severity.NOTICE, id = "TEST-0001"),
            finding(Status.PASS, Severity.CRITICAL, id = "TEST-0002"),
            finding(Status.FAIL, Severity.CRITICAL, id = "TEST-0003"),
            finding(Status.FAIL, Severity.NOTICE, id = "TEST-0004"),
            finding(Status.UNKNOWN, Severity.CRITICAL, id = "TEST-0005"),
        )

        assertEquals(listOf("TEST-0003", "TEST-0001", "TEST-0004"), findings.issues().map { it.spec.id })
    }

    private fun finding(
        status: Status,
        severity: Severity = Severity.WARNING,
        id: String = "TEST-0001",
        title: String = "Test",
        summary: String = "summary",
        category: Category = Category.ACCESS_CONTROL,
    ) = Finding(
        spec = CheckSpec(id, category, title, severity, "Why.", Remediation("Fix it.")),
        status = status,
        severity = severity,
        summary = summary,
        evidence = listOf(Evidence("adb_enabled", "1", Source("Settings.Global \"adb_enabled\""))),
        elapsedMillis = 3,
    )
}
