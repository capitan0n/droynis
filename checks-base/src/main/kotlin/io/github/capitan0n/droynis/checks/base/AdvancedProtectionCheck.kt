package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class AdvancedProtectionCheck(private val policy: DevicePolicy) : Check {

    override val spec = CheckSpec(
        id = "INTG-1030",
        category = Category.DEVICE_INTEGRITY,
        title = "Advanced Protection",
        severity = Severity.INFO,
        explanation = "Advanced Protection (Android 16+) switches on Android's strictest defenses at once, " +
            "for example blocking app installs from unknown sources and 2G connections. It is meant for " +
            "people at higher risk, such as journalists and activists.",
        remediation = Remediation(
            text = "If you are at higher risk, turn it on under Settings › Security & privacy › Advanced " +
                "Protection. It also blocks installing apps from unknown sources, including the F-Droid client.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        minSdk = 36,
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = policy.advancedProtection()
        val evidence = listOf(enabled.toEvidence("Advanced Protection enabled"))
        return enabled.evaluate("Advanced Protection state", evidence) { on ->
            if (on) {
                Outcome.pass("Advanced Protection is on", evidence)
            } else {
                Outcome.fail("Advanced Protection is off", evidence)
            }
        }
    }
}
