package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit

/**
 * The date of the last Google Play system update (Project Mainline): the version name of the module
 * metadata package, which Settings shows under "Google Play system update". These updates patch
 * system components (media codecs, the network stack, Conscrypt, the permission controller…) apart
 * from the vendor's system updates, so this date can be old on a phone whose security patch level
 * looks current, and the other way round.
 */
class PlaySystemUpdateCheck(private val modules: ModuleProbe) : Check {

    override val spec = CheckSpec(
        id = "INTG-1012",
        category = Category.DEVICE_INTEGRITY,
        title = "Google Play system update",
        severity = Severity.NOTICE,
        explanation = "Since Android 10, Google updates parts of the system itself through Google Play, " +
            "apart from the phone maker's system updates: media codecs, the network stack, the certificate " +
            "store and more. They install only after a restart, and a phone can sit on an old one for " +
            "months while its security patch level looks current. Phones without Google's system " +
            "components, such as GrapheneOS or LineageOS, don't get these updates and this check doesn't " +
            "apply to them.",
        remediation = Remediation(
            text = "Open Settings › Security & privacy › System & updates › Google Play system update (on " +
                "Samsung: Settings › Security and privacy › Updates), install what is offered and restart " +
                "the phone. If nothing newer is offered, the phone maker or Google has stopped shipping them " +
                "for this model.",
            settingsActions = listOf(SettingsActions.SECURITY, SettingsActions.DEVICE_INFO),
        ),
        minSdk = 29,
        failsWhen = "the Google Play system update is older than 180 days (a warning when over a year old)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val metadata = modules.metadata()
        val today = context.startedAt.toLocalDate()
        val evidence = listOf(
            metadata.toEvidence("Module metadata") { it?.let { m -> "${m.packageName} \"${m.versionName}\"" } ?: "none" },
            Evidence("Reference date", today.toString(), Source("device clock at scan start")),
        )
        return metadata.evaluate("The Google Play system update", evidence) { found ->
            if (found == null) {
                return@evaluate Outcome.unsupported("This phone has no Google Play system updates", evidence)
            }
            val date = parse(found.versionName)
            if (date == null) {
                // AOSP's own placeholder package carries a plain version, not a date: no Google modules.
                return@evaluate if (found.packageName == GOOGLE_PROVIDER) {
                    Outcome.unknown("Unrecognized Google Play system update version \"${found.versionName}\"", evidence)
                } else {
                    Outcome.unsupported("This Android build doesn't get Google Play system updates", evidence)
                }
            }
            val age = ChronoUnit.DAYS.between(date, today)
            when {
                age < -SecurityPatchAgeCheck.MAX_DAYS_AHEAD ->
                    Outcome.unknown("Google Play system update $date is ${-age} days ahead of the device clock", evidence)
                age <= 0 -> Outcome.pass("Google Play system update $date is current", evidence)
                age <= CURRENT_DAYS -> Outcome.pass("Google Play system update $date is $age days old", evidence)
                age <= STALE_DAYS -> Outcome.fail("Google Play system update $date is $age days old", evidence)
                else -> Outcome.fail(
                    "Google Play system update $date is $age days old, over a year",
                    evidence,
                    escalation = Severity.WARNING,
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
        /** Google's module metadata package; its version name is the update's date. */
        const val GOOGLE_PROVIDER = "com.google.android.modulemetadata"

        /** These updates come less regularly than security bulletins and reach some models months late. */
        const val CURRENT_DAYS = 180L

        /** Beyond a year the FAIL escalates to a warning. */
        const val STALE_DAYS = 365L
    }
}
