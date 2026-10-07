package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import java.time.DateTimeException
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlin.time.Duration.Companion.seconds

/**
 * Whether the vendor image and the kernel keep up with Android's own patch level. The secure hardware
 * attests both (Keymaster 4 and later); the vendor's system property is the fallback. Android's own
 * patch age is [SecurityPatchAgeCheck]'s job, so this check only looks at the gap.
 */
class VendorPatchCheck(
    private val build: BuildInfo,
    private val attestation: AttestationProbe,
    private val properties: SystemProperties,
) : Check {

    override val spec = CheckSpec(
        id = "INTG-1011",
        category = Category.DEVICE_INTEGRITY,
        title = "Vendor and kernel patch level",
        severity = Severity.WARNING,
        explanation = "Android's security patch date covers the parts Google ships. The kernel and the vendor " +
            "image, with the drivers and the hardware layer, are patched separately, and the modem firmware " +
            "is updated along with them. When they fall months behind Android's patch, as on custom ROMs that " +
            "run on old firmware or phones whose maker updates only Android, their known holes stay open; " +
            "kernel and GPU driver bugs are among the most exploited on Android.",
        remediation = Remediation(
            text = "Install every system update. On a custom ROM, flash the newest firmware (vendor and modem " +
                "images) for your device, or move to a ROM that ships it. A phone whose maker stopped firmware " +
                "updates can't be fully patched.",
        ),
        // Generating an attested key in secure hardware can take a few seconds.
        timeout = 20.seconds,
        failsWhen = "the vendor or kernel patch is more than 90 days older than Android's (critical beyond a year)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val android = build.securityPatch()
        val attested = attestation.attest()
        val props = properties.all()
        val propValues = (props as? Reading.Value)?.value.orEmpty()

        // A software attestation comes from the OS being judged; only secure hardware is trusted.
        val hardware = (attested as? Reading.Value)?.value?.takeIf { it.securityLevel != SecurityLevel.SOFTWARE }
        val vendor = hardware?.vendorPatchLevel?.let(::patchDate)?.let { Part("Vendor", it, attested.source, "attested") }
            ?: propValues[VENDOR_PATCH]?.let(::parseDate)?.let { Part("Vendor", it, props.source, VENDOR_PATCH) }
        val kernel = hardware?.bootPatchLevel?.let(::patchDate)?.let { Part("Kernel", it, attested.source, "attested") }
        val androidDate = (android as? Reading.Value)?.value?.let(::parseDate)

        val evidence = buildList {
            add(android.toEvidence("Android patch level"))
            add(vendor?.evidence() ?: Evidence("Vendor patch level", null, props.source, "not reported"))
            add(kernel?.evidence() ?: Evidence("Kernel patch level", null, attested.source, "not reported"))
            if (hardware == null) add(attested.toEvidence("Key attestation") { "software only, not trusted" })
            val baseband = propValues[BASEBAND]?.takeIf { it.isNotBlank() }
            add(Evidence("Modem firmware (baseband)", baseband, props.source, note = if (baseband == null) "not readable" else null))
        }
        if (androidDate == null) return Outcome.unknown("Android's patch level could not be read", evidence)
        val parts = listOfNotNull(vendor, kernel)
        if (parts.isEmpty()) {
            return if (attested is Reading.Unavailable) {
                Outcome.unknown("The vendor and kernel patch levels could not be read", evidence)
            } else {
                Outcome.unsupported("This phone reports neither a vendor nor a kernel patch level", evidence)
            }
        }

        val behind = parts.map { it to ChronoUnit.DAYS.between(it.date, androidDate) }.sortedByDescending { it.second }
        val (worst, days) = behind.first()
        val androidLabel = format(androidDate)
        return when {
            days > STALE_DAYS -> Outcome.fail(
                "The ${worst.name.lowercase()} patch (${format(worst.date)}) is over a year behind Android's ($androidLabel)",
                evidence,
                escalation = Severity.CRITICAL,
            )
            days > CURRENT_DAYS -> Outcome.fail(
                "The ${worst.name.lowercase()} patch (${format(worst.date)}) is $days days behind Android's ($androidLabel)",
                evidence,
            )
            kernel == null ->
                Outcome.pass("The vendor patch keeps up with Android's ($androidLabel); the kernel's isn't reported", evidence)
            vendor == null ->
                Outcome.pass("The kernel patch keeps up with Android's ($androidLabel); the vendor's isn't reported", evidence)
            else -> Outcome.pass("The vendor and kernel patches keep up with Android's ($androidLabel)", evidence)
        }
    }

    private class Part(val name: String, val date: LocalDate, val source: Source, val how: String) {
        fun evidence() = Evidence("$name patch level", format(date), source, note = how)
    }

    companion object {
        const val VENDOR_PATCH = "ro.vendor.build.security_patch"
        const val BASEBAND = "gsm.version.baseband"

        /** One quarterly release plus rollout, as for Android's own patch. */
        const val CURRENT_DAYS = SecurityPatchAgeCheck.CURRENT_DAYS
        const val STALE_DAYS = SecurityPatchAgeCheck.STALE_DAYS

        /** YYYYMMDD, or YYYYMM from some Keymaster versions; null for anything that isn't a date. */
        fun patchDate(value: Int): LocalDate? = try {
            when {
                value >= 10_000_000 -> LocalDate.of(value / 10_000, value / 100 % 100, (value % 100).coerceAtLeast(1))
                value >= 100_000 -> LocalDate.of(value / 100, value % 100, 1)
                else -> null
            }?.takeIf { it.year >= MIN_YEAR }
        } catch (e: DateTimeException) {
            null
        }

        private fun parseDate(raw: String): LocalDate? = try {
            LocalDate.parse(raw.trim()).takeIf { it.year >= MIN_YEAR }
        } catch (e: DateTimeParseException) {
            null
        }

        private fun format(date: LocalDate): String = date.toString()

        /** Patch levels started in 2015; anything earlier is a placeholder. */
        private const val MIN_YEAR = 2015
    }
}
