package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class HardeningIndexTest {

    private var nextId = 1000

    @Test
    fun `no evaluated checks means no score rather than 0 or 100`() {
        assertNull(HardeningIndex.of(emptyList()).score)
        val skippedOnly = HardeningIndex.of(listOf(finding(Status.UNKNOWN), finding(Status.UNSUPPORTED)))
        assertNull(skippedOnly.score)
        assertEquals(2, skippedOnly.skipped)
    }

    @Test
    fun `info checks never move the score`() {
        assertNull(HardeningIndex.of(listOf(finding(Status.FAIL, Severity.INFO))).score)
        val mixed = listOf(finding(Status.PASS, Severity.WARNING), finding(Status.FAIL, Severity.INFO))
        assertEquals(100, HardeningIndex.of(mixed).score)
    }

    @Test
    fun `score is the weighted share of passes`() {
        val findings = listOf(
            finding(Status.PASS, Severity.WARNING), // 5
            finding(Status.PASS, Severity.NOTICE), // 2
            finding(Status.FAIL, Severity.WARNING), // 5
            finding(Status.UNKNOWN, Severity.CRITICAL), // ignored
        )

        val index = HardeningIndex.of(findings)

        assertEquals(58, index.score) // 7 / 12, floored
        assertEquals(58, index.uncappedScore)
        assertEquals(2, index.passed)
        assertEquals(3, index.evaluated)
        assertEquals(1, index.skipped)
        assertEquals(mapOf(Severity.WARNING to 1), index.failed)
    }

    @Test
    fun `a single failure keeps the score below 100`() {
        val findings = List(500) { finding(Status.PASS, Severity.CRITICAL) } + finding(Status.FAIL, Severity.NOTICE)

        assertEquals(99, HardeningIndex.of(findings).score)
    }

    @Test
    fun `a critical failure caps the score however many checks pass`() {
        val findings = List(50) { finding(Status.PASS, Severity.WARNING) } + finding(Status.FAIL, Severity.CRITICAL)

        val index = HardeningIndex.of(findings)

        assertEquals(HardeningIndex.CRITICAL_CAP, index.score)
        assertEquals(96, index.uncappedScore) // 250 / 260: the progress the cap hides
        assertEquals(listOf(findings.last().spec.id), index.cappedBy)
    }

    @Test
    fun `an escalated failure caps the score but keeps its declared weight`() {
        val escalated = finding(Status.FAIL, declared = Severity.WARNING, effective = Severity.CRITICAL)
        val findings = listOf(finding(Status.PASS, Severity.WARNING), escalated)

        val index = HardeningIndex.of(findings)

        assertEquals(40, index.score) // 5 / 10 = 50, capped to 40
        assertEquals(mapOf(Severity.CRITICAL to 1), index.failed)
    }

    @Test
    fun `muted checks leave the score and every count, but are listed`() {
        val patch = finding(Status.FAIL, Severity.WARNING)
        val findings = listOf(finding(Status.PASS, Severity.WARNING), patch, finding(Status.UNKNOWN))

        val index = HardeningIndex.of(findings, muted = setOf(patch.spec.id, "TEST-9999"))

        assertEquals(100, index.score) // 5 / 5 once the failing check is muted
        assertEquals(1, index.passed)
        assertEquals(emptyMap(), index.failed)
        assertEquals(1, index.unknown)
        assertEquals(listOf(patch.spec.id), index.muted) // ids not in this scan are not reported
        assertEquals(50, HardeningIndex.of(findings).score)
    }

    @Test
    fun `a muted critical failure no longer caps the score`() {
        val root = finding(Status.FAIL, Severity.CRITICAL)
        val findings = listOf(finding(Status.PASS, Severity.WARNING), root)

        val index = HardeningIndex.of(findings, muted = setOf(root.spec.id))

        assertEquals(100, index.score)
        assertEquals(emptyList(), index.cappedBy)
    }

    private fun finding(
        status: Status,
        declared: Severity = Severity.WARNING,
        effective: Severity = declared,
    ) = Finding(
        spec = CheckSpec(
            id = "TEST-${nextId++}",
            category = Category.ACCESS_CONTROL,
            title = "Test check $nextId",
            severity = declared,
            explanation = "Why it matters.",
            remediation = Remediation("Fix it."),
        ),
        status = status,
        severity = effective,
        summary = "summary",
        evidence = emptyList(),
        elapsedMillis = 1,
    )
}
