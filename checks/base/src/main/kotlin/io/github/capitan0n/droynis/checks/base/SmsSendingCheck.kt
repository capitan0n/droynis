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

/** Apps that may send SMS, the permission premium-SMS billing fraud needs. */
class SmsSendingCheck(
    private val permissions: PermissionProbe,
    private val defaults: DefaultAppsProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4009",
        category = Category.APPS,
        title = "Apps that can send SMS",
        severity = Severity.NOTICE,
        explanation = "An app that can send SMS can text premium-rate numbers that are charged to your phone " +
            "bill, or send messages in your name, without opening your messaging app; billing-fraud malware " +
            "such as Joker does exactly that. Android asks before an app texts a premium number, unless its " +
            "Premium SMS access is set to Always allow. Your SMS app needs this permission and apps that came " +
            "with the phone are listed but don't count; any other app deserves a look, and one installed from " +
            "outside an app store is a warning.",
        remediation = Remediation(
            text = "Open Settings › Apps › the app › Permissions and set SMS to \"Don't allow\" for apps that don't " +
                "need it. Under Settings › Apps › Special app access › Premium SMS access, keep every app on Ask " +
                "or Never allow. Uninstall apps you don't recognize.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an app other than your SMS app can send SMS (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val granted = permissions.holders(SEND)
        val sms = defaults.smsApp()
        val smsEvidence = sms.toEvidence("Default SMS app") { pkg -> pkg?.let { "${packages.label(it)} ($it)" } ?: "none" }
        if (granted !is Reading.Value) {
            val evidence = listOf(smsEvidence, granted.toEvidence("Permissions"))
            return Outcome.unknown("Could not read which apps can send SMS", evidence)
        }
        val smsApp = (sms as? Reading.Value)?.value
        val inventory = packages.byPackage()

        val all = holders(
            granted.value.keys.filter { it != smsApp }.sorted().map { AppRef(it, packages.label(it)) },
            inventory,
        )
        val counted = all.filter { it.origin != AppOrigin.PREINSTALLED }
        val evidence = buildList {
            add(smsEvidence)
            counted.forEach { add(it.evidence("Can send SMS", granted.source)) }
            val preinstalled = all.size - counted.size
            if (preinstalled > 0) {
                add(Evidence("Apps that came with the phone and can send SMS", preinstalled.toString(), granted.source))
            }
        }
        if (counted.isEmpty()) {
            return Outcome.pass("Only your SMS app and apps that came with the phone can send SMS", evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} can send SMS: ${counted.map { it.app.label }.joinNames()}" + sideloadedSuffix(counted),
            evidence,
            escalation = sideloadedEscalation(counted),
        )
    }

    companion object {
        val SEND = setOf("android.permission.SEND_SMS")
    }
}
