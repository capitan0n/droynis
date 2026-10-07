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
            "from outside an app store is a warning.",
        remediation = Remediation(
            text = "Open Settings › Apps › the app › Permissions and set SMS and Call logs to \"Don't allow\" " +
                "for apps that don't need them. Uninstall apps you don't recognize.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an app other than your SMS and phone apps can read SMS or the call log " +
            "(a warning when it came from outside an app store)",
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

        // What each app holds beyond what its role explains.
        val unexplained = granted.value.mapValues { (pkg, held) ->
            held.filterNot { (pkg == smsApp && it in SMS) || (pkg == phoneApp && it in CALL_LOG) }.toSet()
        }.filterValues { it.isNotEmpty() }
        val all = unexplained.map { (pkg, held) -> Holder(AppRef(pkg, packages.label(pkg)), originOf(pkg, inventory)) to held }
        val counted = all.filter { (holder, _) -> holder.origin != AppOrigin.PREINSTALLED }
        val preinstalled = all.size - counted.size

        val evidence = buildList {
            addAll(defaultsEvidence)
            counted.forEach { (holder, held) ->
                add(
                    Evidence(
                        "Can read your ${describe(held)}",
                        "${holder.app.label} (${holder.app.packageName})",
                        granted.source,
                        note = holder.origin.note,
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
