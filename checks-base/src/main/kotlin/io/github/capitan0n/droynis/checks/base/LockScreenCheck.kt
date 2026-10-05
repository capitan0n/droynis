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

class LockScreenCheck(private val keyguard: Keyguard) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2001",
        category = Category.ACCESS_CONTROL,
        title = "Secure lock screen",
        severity = Severity.CRITICAL,
        explanation = "Without a PIN, pattern or password, anyone holding the device can use it, and " +
            "the encryption of your data is not tied to any secret you know. Biometrics and apps " +
            "that protect their keys with your screen lock depend on it too.",
        remediation = Remediation(
            text = "Set a PIN or password. A PIN of 6 or more digits or an alphanumeric password is " +
                "much stronger than a pattern.",
            settingsActions = listOf(SettingsActions.SET_NEW_PASSWORD, SettingsActions.SECURITY),
        ),
        failsWhen = "no PIN, pattern or password is set",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val secure = keyguard.isDeviceSecure()
        val evidence = listOf(
            secure.toEvidence("Device secure"),
            keyguard.passwordComplexity().toEvidence("Lock complexity") { it.name },
        )
        return secure.evaluate("Lock screen state", evidence) { isSecure ->
            if (isSecure) {
                Outcome.pass("A PIN, pattern or password is set", evidence)
            } else {
                Outcome.fail("No PIN, pattern or password is set", evidence)
            }
        }
    }
}
