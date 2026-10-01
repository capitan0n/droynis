package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit

class SecurityPatchAgeCheck(private val build: BuildInfo) : Check {

    override val spec = CheckSpec(
        id = "INTG-1010",
        category = Category.DEVICE_INTEGRITY,
        title = "Security patch age",
        severity = Severity.WARNING,
        explanation = "The security patch level is the date of the newest Android security bulletin " +
            "the OS says it includes. Since 2025 most fixes ship in quarterly releases, so a level " +
            "older than about 90 days has missed at least one, and publicly known vulnerabilities " +
            "stay open.",
        remediation = Remediation(
            text = "Install pending system updates (Settings › System › Software update; the location " +
                "varies by vendor). If the vendor no longer ships updates, the device is end-of-life: " +
                "plan to replace it or move to a maintained OS that supports relocking the bootloader.",
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val patch = build.securityPatch()
        val today = context.startedAt.toLocalDate()
        val evidence = listOf(
            patch.toEvidence("Security patch level") { "\"$it\"" },
            Evidence("Reference date", today.toString(), Source("device clock at scan start")),
        )
        return patch.evaluate("Security patch level", evidence) { raw ->
            val date = parse(raw)
                ?: return@evaluate Outcome.unknown("Unrecognized security patch level \"$raw\"", evidence)
            val age = ChronoUnit.DAYS.between(date, today)
            when {
                age < -MAX_DAYS_AHEAD ->
                    Outcome.unknown("Patch level $date is ${-age} days ahead of the device clock", evidence)
                age <= 0 -> Outcome.pass("Patch level $date is current", evidence)
                age <= CURRENT_DAYS -> Outcome.pass("Patch level $date is $age days old", evidence)
                age <= STALE_DAYS -> Outcome.fail("Patch level $date is $age days old", evidence)
                else -> Outcome.fail(
                    "Patch level $date is $age days old, over a year",
                    evidence,
                    escalation = Severity.CRITICAL,
                )
            }
        }
    }

    private fun parse(raw: String): LocalDate? =
        try {
            LocalDate.parse(raw.trim())
        } catch (e: DateTimeParseException) {
            null
        }

    companion object {
        /** Up to one quarterly release plus OEM rollout time counts as current. */
        const val CURRENT_DAYS = 90L

        /** Beyond a year the FAIL escalates to CRITICAL. */
        const val STALE_DAYS = 365L

        /** OEMs sometimes ship next month's level early; further ahead means the clock is wrong. */
        const val MAX_DAYS_AHEAD = 45L
    }
}
