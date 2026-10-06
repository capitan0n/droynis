package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class LockStrengthCheck(private val keyguard: Keyguard) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2007",
        category = Category.ACCESS_CONTROL,
        title = "Screen lock strength",
        severity = Severity.NOTICE,
        explanation = "A pattern can be read from smudges on the screen or by watching over your shoulder, " +
            "and a PIN such as 1234 or 1111 is among the first anyone tries. Android rates the screen lock " +
            "low, medium or high without revealing it: low means a pattern, or a PIN with repeated or " +
            "ordered digits.",
        remediation = Remediation(
            text = "Change the screen lock to a PIN of 6 or more digits without repeated or ordered digits, " +
                "or to a password (Settings › Security › Screen lock).",
            settingsActions = listOf(SettingsActions.SET_NEW_PASSWORD, SettingsActions.SECURITY),
        ),
        // DevicePolicyManager.getPasswordComplexity() exists from Android 10.
        minSdk = 29,
        failsWhen = "the screen lock is a pattern or a PIN with repeated or ordered digits",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val secure = keyguard.isDeviceSecure()
        val complexity = keyguard.passwordComplexity()
        val evidence = listOf(
            secure.toEvidence("Device secure"),
            complexity.toEvidence("Lock complexity") { it.name },
        )
        if (secure is Reading.Value && !secure.value) {
            return Outcome.unsupported("No screen lock is set; Secure lock screen (ACCS-2001) covers that", evidence)
        }
        return complexity.evaluate("Screen lock strength", evidence) { level ->
            when (level) {
                PasswordComplexity.LOW -> Outcome.fail("The screen lock is a pattern or a simple PIN", evidence)
                PasswordComplexity.MEDIUM -> Outcome.pass("The screen lock is of medium strength", evidence)
                PasswordComplexity.HIGH -> Outcome.pass("The screen lock is strong", evidence)
                // A lock is set, or unknown, yet Android reports none: nothing to rely on.
                PasswordComplexity.NONE -> Outcome.unknown("Android reports no screen lock strength", evidence)
            }
        }
    }
}
