package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.Keyguard
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

class MagiskPromptCheck(private val root: RootShellProbe, private val keyguard: Keyguard) : Check {
    override val spec = CheckSpec(
        id = "ACCS-2302",
        category = Category.ACCESS_CONTROL,
        title = "Magisk superuser prompt protections",
        severity = Severity.NOTICE,
        explanation = "User authentication asks you to unlock before approving a root request. " +
            "Tapjacking protection ignores touches while another window covers the prompt. " +
            "These settings apply when Magisk shows a prompt. Existing grants are listed in APPS-4301.",
        remediation = Remediation("Open Magisk settings and review User authentication and Tapjacking protection under Superuser. " +
            "User authentication also needs a PIN, pattern or password. Available switches depend on your Magisk version."),
        requires = setOf(Grant.ROOT),
        timeout = 25.seconds,
        failsWhen = "user authentication or tapjacking protection is confirmed off for Magisk prompts",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val manager = root.manager()
        if (manager !is Reading.Value) return Outcome.unknown("Could not identify the root manager")
        if (manager.value != RootManager.MAGISK) return Outcome.unsupported("This check applies to Magisk")
        val version = root.magiskVersion()
        if (version !is Reading.Value || version.value !in 25200..31100) return Outcome.unknown("Unrecognized Magisk prompt model")
        if (version.value == 31100) return Outcome.unsupported("Magisk 31.1 grants root in advance and has no interactive root prompts")
        if (context.appUid?.div(100_000) != 0) return Outcome.unsupported("Check Magisk's prompts from the owner profile")

        val settings = root.magiskSettings()
        val values = (settings as? Reading.Value)?.let { MagiskSettings.parse(it.value) }
        val lock = keyguard.isDeviceSecure()
        val secure = (lock as? Reading.Value)?.value
        // Magisk defaults su_biometric to false and requires a secure lock even with the flag set.
        val auth = when {
            secure == false -> false
            values == null -> null
            else -> when (values["su_biometric"] ?: 0) {
                0 -> false
                1 -> secure
                else -> null
            }
        }
        val tapjack = root.tapjackingProtection()
        if (tapjack is Reading.Unsupported) return Outcome.unsupported(tapjack.reason)
        val overlay = (tapjack as? Reading.Value)?.value
        val evidence = listOf(
            Evidence("User authentication", auth?.let { if (it) "on" else "off" }, settings.source,
                note = when {
                    secure == false -> "no secure device lock"
                    values != null && "su_biometric" !in values -> "Magisk default"
                    auth == null -> "setting or lock state unreadable"
                    else -> null
                }),
            lock.toEvidence("Secure device lock"),
            tapjack.toEvidence("Tapjacking protection") { if (it) "on" else "off" },
        )
        val off = listOfNotNull("user authentication".takeIf { auth == false }, "tapjacking protection".takeIf { overlay == false })
        return when {
            off.isNotEmpty() -> Outcome.fail("Magisk prompt protections turned off: ${off.joinToString(" and ")}", evidence)
            auth == true && overlay == true -> Outcome.pass("Both Magisk prompt protections are on", evidence)
            else -> Outcome.unknown("Could not confirm both Magisk prompt protections", evidence)
        }
    }
}
