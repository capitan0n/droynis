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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps granted location "All the time": ACCESS_BACKGROUND_LOCATION together with a foreground
 * location permission, from `PackageManager` (granted flags, not just requested). Apps built for
 * Android 9 or older get the background permission with the foreground one, and show up the same way.
 */
class BackgroundLocationCheck(
    private val permissions: PermissionProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4012",
        category = Category.APPS,
        title = "Apps with location all the time",
        severity = Severity.NOTICE,
        explanation = "An app allowed location \"All the time\" can see where you are while you aren't " +
            "using it, and build a history of the places you go. Navigation, fitness and find-my-phone " +
            "apps may need it; most apps work with \"Only while using the app\". Apps that came with the " +
            "phone are listed but don't count; one installed from outside an app store is a warning, as " +
            "stalkerware asks for exactly this.",
        remediation = Remediation(
            text = "Open Settings › Location › App location permissions (on some phones Settings › Privacy › " +
                "Permission manager › Location) and set the apps listed to \"Allow only while using the app\" " +
                "or \"Don't allow\".",
            settingsActions = listOf(SettingsActions.LOCATION),
        ),
        // ACCESS_BACKGROUND_LOCATION exists from Android 10; before it, any location grant was "all the time".
        minSdk = 29,
        timeout = 15.seconds,
        failsWhen = "an app you installed may use location all the time (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val granted = permissions.holders(setOf(BACKGROUND) + FOREGROUND)
        if (granted !is Reading.Value) {
            return Outcome.unknown("Could not read which apps hold location permissions", listOf(granted.toEvidence("Permissions")))
        }
        val always = granted.value.filterValues { held -> BACKGROUND in held && held.any { it in FOREGROUND } }.keys
        val inventory = packages.byPackage()
        // Preinstalled holders are only counted, so only the others need a label.
        val origins = always.associateWith { originOf(it, inventory) }
        val counted = always.filter { origins.getValue(it) != AppOrigin.PREINSTALLED }
            .map { Holder(AppRef(it, packages.label(it)), origins.getValue(it)) }
            .sortedBy { it.app.label.lowercase() }
        val preinstalled = always.size - counted.size

        val evidence = buildList {
            counted.forEach { add(it.evidence("Location all the time", granted.source)) }
            if (preinstalled > 0) {
                add(Evidence("Apps that came with the phone with location all the time", preinstalled.toString(), granted.source))
            }
            if (isEmpty()) add(Evidence("Location all the time", "none", granted.source))
        }
        if (counted.isEmpty()) {
            val summary = if (preinstalled > 0) {
                "Only apps that came with the phone may use location all the time"
            } else {
                "No app may use location all the time"
            }
            return Outcome.pass(summary, evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} may use location all the time: ${counted.map { it.app.label }.joinNames()}" +
                sideloadedSuffix(counted),
            evidence,
            escalation = sideloadedEscalation(counted),
        )
    }

    companion object {
        const val BACKGROUND = "android.permission.ACCESS_BACKGROUND_LOCATION"
        val FOREGROUND = setOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION")
    }
}
