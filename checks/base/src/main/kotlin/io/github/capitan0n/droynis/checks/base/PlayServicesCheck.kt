package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

/**
 * Which Google Play services the phone runs. microG installs under Google's package name, and
 * signature spoofing can make it report Google's key, so microG's own activities (or its key) mark
 * it first; only then does Google's key mean Google's code. Built into the system image it gets
 * privileged permissions; installed as an ordinary app, like GrapheneOS's sandboxed Google Play,
 * it gets none. `MATCH_SYSTEM_ONLY` asks the package manager's own record, which GrapheneOS doesn't
 * change, unlike the flags apps are shown.
 */
class PlayServicesCheck(private val packages: PackageDetailsProbe) : Check {

    override val spec = CheckSpec(
        id = "APPS-4014",
        category = Category.APPS,
        title = "Google Play services",
        severity = Severity.INFO,
        explanation = "Google Play services is the layer behind Google sign-in, push notifications, location " +
            "services and the advertising ID, and it shares device data with Google. Built into the system, " +
            "as on most phones, it holds privileged access that no ordinary app can have and that you can't " +
            "take back. Installed as an ordinary app, as GrapheneOS's sandboxed Google Play is, it gets only " +
            "the permissions you grant; microG is an open-source replacement that shares far less.",
        remediation = Remediation(
            text = "Information only: on most phones it can't be removed without replacing the operating system. " +
                "To limit it, turn off the Google features you don't use (Settings › Google), delete the " +
                "advertising ID (Settings › Privacy › Ads) and review its permissions in App info. GrapheneOS, " +
                "or a microG-based system such as /e/OS or LineageOS for microG, runs without it in the system.",
            settingsActions = listOf(SettingsActions.PRIVACY),
        ),
        failsWhen = "Google Play services is built into the system, with privileged access (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val read = packages.details(GMS)
        val readEvidence = read.toEvidence("Google Play services") { if (it == null) "not installed" else "installed" }
        return read.evaluate("Google Play services", listOf(readEvidence)) { details ->
            if (details == null) {
                Outcome.pass("Google Play services isn't installed", listOf(readEvidence))
            } else {
                judge(details, read.source)
            }
        }
    }

    private fun judge(details: PackageDetails, source: Source): Outcome {
        val microgActivities = details.activities?.filter { it.startsWith(MICROG_PREFIX) }.orEmpty()
        val microg = microgActivities.isNotEmpty() || MICROG_SIGNER in details.signerSha1
        val google = details.signerSha1.any { it in GOOGLE_SIGNERS }
        val evidence = listOf(
            Evidence("Package", GMS, source, packageName = GMS),
            Evidence("Enabled", yesNo(details.isEnabled), source),
            Evidence("In the system image", yesNo(details.inSystemImage), source, note = "MATCH_SYSTEM_ONLY"),
            Evidence(
                "Signing certificate (SHA-1)",
                details.signerSha1.sorted().joinToString().ifEmpty { null },
                source,
                note = when {
                    details.signerSha1.isEmpty() -> "not readable"
                    MICROG_SIGNER in details.signerSha1 -> "microG's key"
                    google -> "Google's key"
                    else -> "neither Google's nor microG's key"
                },
            ),
            Evidence(
                "microG activities",
                when {
                    details.activities == null -> null
                    microgActivities.isEmpty() -> "none"
                    else -> count(microgActivities.size, "activity", "activities") + ", e.g. ${microgActivities.first()}"
                },
                source,
                note = if (details.activities == null) "not readable" else null,
            ),
        )

        return when {
            microg -> Outcome.pass("microG, an open-source replacement, stands in for Google Play services", evidence)
            details.signerSha1.isEmpty() -> Outcome.unknown("Couldn't read who signed $GMS", evidence)
            !google -> Outcome.unknown("$GMS is signed by neither Google nor microG", evidence)
            !details.isEnabled -> Outcome.pass("Google Play services is installed but turned off", evidence)
            // A spoofed signature could hide microG; without the activities that can't be ruled out.
            details.activities == null ->
                Outcome.unknown("Couldn't rule out microG: the package's activities couldn't be read", evidence)
            details.inSystemImage ->
                Outcome.fail("Google Play services is built into the system, with privileged access", evidence)
            else -> Outcome.pass("Google Play services runs as an ordinary app, without system privileges", evidence)
        }
    }

    private fun yesNo(value: Boolean) = if (value) "yes" else "no"

    companion object {
        const val GMS = "com.google.android.gms"

        /** microG's activities live under its own namespace, whatever package name it installs as. */
        const val MICROG_PREFIX = "org.microg."

        /**
         * The keys that sign Google's Play services, as SHA-1 certificate fingerprints. From microG's
         * own list (`org.microg.gms.common.Constants`: GMS_PACKAGE_SIGNATURE_SHA1 and
         * GMS_SECONDARY_PACKAGE_SIGNATURE_SHA1), which it checks to recognize the real thing.
         */
        val GOOGLE_SIGNERS = setOf(
            "38918a453d07199354f8b19af05ec6562ced5788",
            "bd32424203e0fb25f36b57e5aa356f9bdd1da998",
        )

        /** microG's release key (MICROG_PACKAGE_SIGNATURE_SHA1 in the same file). */
        const val MICROG_SIGNER = "10321bd893f69af97f7573aafe9de1dc0901f3a1"
    }
}
