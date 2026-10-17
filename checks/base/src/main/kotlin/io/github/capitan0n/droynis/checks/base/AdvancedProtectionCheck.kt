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
import kotlin.time.Duration.Companion.seconds

class AdvancedProtectionCheck(
    private val policy: DevicePolicy,
    private val webView: WebViewProbe,
    private val packages: PackageInventory,
) : Check {

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
                "Protection. It also blocks installing apps from unknown sources, including the F-Droid client. " +
                "GrapheneOS has no such switch, so this check doesn't apply there: it offers similar protections " +
                "one by one under Settings › Security & privacy › Exploit protection.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        minSdk = 36,
        // Telling GrapheneOS apart may read the app list, which takes a few seconds on some phones.
        timeout = 15.seconds,
        failsWhen = "Advanced Protection is off",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = policy.advancedProtection()
        val evidence = listOf(enabled.toEvidence("Advanced Protection enabled"))
        return enabled.evaluate("Advanced Protection state", evidence) { on ->
            if (on) return@evaluate Outcome.pass("Advanced Protection is on", evidence)
            // GrapheneOS reports it off but has no switch for it, so a FAIL would ask for the impossible.
            val grapheneOs = GrapheneOs.signs(webView, packages)
            if (grapheneOs.isEmpty()) {
                Outcome.fail("Advanced Protection is off", evidence)
            } else {
                Outcome.unsupported(GRAPHENEOS_SUMMARY, evidence + grapheneOs)
            }
        }
    }

    companion object {
        const val GRAPHENEOS_SUMMARY = "GrapheneOS has no Advanced Protection switch; it offers similar " +
            "protections one by one under Settings › Security & privacy › Exploit protection"
    }
}
