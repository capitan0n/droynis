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

class SmsAccessCheck(
    private val permissions: PermissionProbe,
    private val defaults: DefaultAppsProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4008",
        category = Category.APPS,
        title = "Apps that can read your SMS or call log",
        severity = Severity.NOTICE,
        explanation = "One-time login codes arrive by SMS, so an app that reads SMS can take over accounts " +
            "protected by them; SMS-stealing apps are among the most common Android malware. The call log " +
            "shows who you talk to. Your SMS and phone apps need these permissions and apps that came " +
            "with the phone are listed but don't count; any other app deserves a look, and one installed " +
            "from outside an app store is a warning, your SMS or phone app included.",
        remediation = Remediation(
            text = "Open Settings › Apps › the app › Permissions and set SMS and Call logs to \"Don't allow\" " +
                "for apps that don't need them. Uninstall apps you don't recognize.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an app other than your SMS and phone apps, or one of those installed from outside an " +
            "app store, can read SMS or the call log (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val granted = permissions.holders(SMS + CALL_LOG)
        val sms = defaults.smsApp()
        val phone = defaults.phoneApp()
        val defaultsEvidence = listOf(
            sms.toEvidence("Default SMS app") { pkg -> pkg?.let { "${packages.label(it)} ($it)" } ?: "none" },
            phone.toEvidence("Default phone app") { pkg -> pkg?.let { "${packages.label(it)} ($it)" } ?: "none" },
        )
        if (granted !is Reading.Value) {
            return Outcome.unknown("Could not read which apps hold these permissions", defaultsEvidence + granted.toEvidence("Permissions"))
        }
        val smsApp = (sms as? Reading.Value)?.value
        val phoneApp = (phone as? Reading.Value)?.value
        val inventory = packages.byPackage()

        // What each app holds beyond what its role explains. A sideloaded default app is counted
        // anyway: holding the role is how an SMS stealer gets every login code.
        fun explained(pkg: String, permission: String) =
            ((pkg == smsApp && permission in SMS) || (pkg == phoneApp && permission in CALL_LOG)) &&
                originOf(pkg, inventory) != AppOrigin.SIDELOADED
        val unexplained = granted.value.mapValues { (pkg, held) ->
            held.filterNot { explained(pkg, it) }.toSet()
        }.filterValues { it.isNotEmpty() }
        // Preinstalled holders are only counted, so only the others need a label: loading one opens
        // that app's resources, and a phone can have dozens of preinstalled holders.
        val origins = unexplained.mapValues { (pkg, _) -> originOf(pkg, inventory) }
        val counted = unexplained.filterKeys { origins.getValue(it) != AppOrigin.PREINSTALLED }
            .map { (pkg, held) -> Holder(AppRef(pkg, packages.label(pkg)), origins.getValue(pkg)) to held }
        val preinstalled = unexplained.size - counted.size

        val evidence = buildList {
            addAll(defaultsEvidence)
            counted.forEach { (holder, held) ->
                add(
                    Evidence(
                        "Can read your ${describe(held)}",
                        "${holder.app.label} (${holder.app.packageName})",
                        granted.source,
                        note = holder.origin.note + roleNote(holder.app.packageName, smsApp, phoneApp),
                    ),
                )
            }
            if (preinstalled > 0) add(Evidence("Apps that came with the phone and can read them", preinstalled.toString(), granted.source))
        }
        if (counted.isEmpty()) {
            return Outcome.pass("Only your SMS and phone apps and apps that came with the phone can read SMS or the call log", evidence)
        }
        val holders = counted.map { it.first }
        return Outcome.fail(
            "${count(holders.size, "app")} can read your SMS or call log: ${holders.map { it.app.label }.joinNames()}" +
                sideloadedSuffix(holders),
            evidence,
            escalation = sideloadedEscalation(holders),
        )
    }

    /** "; your default SMS app", or nothing. */
    private fun roleNote(pkg: String, smsApp: String?, phoneApp: String?): String {
        val roles = listOfNotNull("SMS".takeIf { pkg == smsApp }, "phone".takeIf { pkg == phoneApp })
        return if (roles.isEmpty()) "" else "; your default ${roles.joinToString(" and ")} app"
    }

    private fun describe(held: Set<String>): String = listOfNotNull(
        "SMS".takeIf { held.any { it in SMS } },
        "call log".takeIf { held.any { it in CALL_LOG } },
    ).joinToString(" and ")

    companion object {
        /** Reading the inbox, and catching messages as they arrive. */
        val SMS = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS")
        val CALL_LOG = setOf("android.permission.READ_CALL_LOG")
    }
}
