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

class StorageEncryptionCheck(private val policy: DevicePolicy) : Check {

    override val spec = CheckSpec(
        id = "INTG-1020",
        category = Category.DEVICE_INTEGRITY,
        title = "Storage encryption",
        severity = Severity.CRITICAL,
        explanation = "Encryption keeps your data unreadable if the phone is lost, stolen or its storage " +
            "is copied. Every device that shipped with Android 10 or later must encrypt each user's data " +
            "with keys tied to the screen lock.",
        remediation = Remediation(
            text = "Set a PIN or password, since the encryption keys are tied to it. If storage is not " +
                "encrypted at all, the device or its firmware cannot protect data at rest: back up your " +
                "data and plan to replace it.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val status = policy.encryptionStatus()
        val evidence = listOf(status.toEvidence("Encryption status") { it.name })
        return status.evaluate("Encryption status", evidence) { value ->
            when (value) {
                EncryptionStatus.ACTIVE_PER_USER ->
                    Outcome.pass("Storage is encrypted with per-user keys", evidence)
                EncryptionStatus.ACTIVE -> Outcome.pass("Storage is encrypted", evidence)
                EncryptionStatus.ACTIVE_DEFAULT_KEY ->
                    Outcome.fail("Storage is encrypted with a default key, not tied to your screen lock", evidence)
                EncryptionStatus.ACTIVATING -> Outcome.unknown("Encryption is still in progress", evidence)
                EncryptionStatus.INACTIVE -> Outcome.fail("Storage is not encrypted", evidence)
                EncryptionStatus.UNSUPPORTED -> Outcome.fail("This device does not support storage encryption", evidence)
            }
        }
    }
}
