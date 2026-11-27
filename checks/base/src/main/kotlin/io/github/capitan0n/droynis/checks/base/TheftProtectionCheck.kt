package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class TheftProtectionCheck(private val packages: PackageInventory) : Check {
    override val spec = CheckSpec(
        id = "ACCS-2021",
        category = Category.ACCESS_CONTROL,
        title = "Google theft protection",
        severity = Severity.INFO,
        explanation = "On supported devices, Theft Detection Lock can lock the screen when it detects a snatch. " +
            "Offline Device Lock can lock an unlocked phone after it loses connectivity. Google Play services " +
            "manages these switches, so review them in Settings.",
        remediation = Remediation(
            "Open Settings › Google › All services › Theft protection and check Theft Detection Lock and Offline Device Lock.",
        ),
        minSdk = 29,
        failsWhen = "never (manual review of Google theft protection)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val installed = packages.installedApps()
        return installed.evaluate("The app inventory", listOf(installed.toEvidence("Visible apps") { it.size.toString() })) { apps ->
            val provider = apps.firstOrNull { it.packageName == "com.google.android.gms" }
            val state = when {
                provider == null -> "not found in this profile"
                !provider.isEnabled -> "disabled in this profile"
                else -> "enabled in this profile"
            }
            val evidence = listOf(Evidence("Google Play services", state, installed.source))
            if (provider?.isEnabled == true) {
                Outcome.unknown("Check theft protection switches in Settings", evidence)
            } else {
                Outcome.unsupported("Google Play services is unavailable in this profile", evidence)
            }
        }
    }
}
