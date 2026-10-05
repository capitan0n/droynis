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
import io.github.capitan0n.droynis.core.evaluate
import io.github.capitan0n.droynis.core.toEvidence

class DeviceAdminsCheck(private val policy: DevicePolicy) : Check {

    override val spec = CheckSpec(
        id = "APPS-4002",
        category = Category.APPS,
        title = "Device admin apps",
        severity = Severity.NOTICE,
        explanation = "Device admin apps can lock or wipe the phone and enforce password rules; a device " +
            "or profile owner can manage it completely. Find-my-device and work profiles use this " +
            "legitimately; anything you do not recognize deserves a closer look.",
        remediation = Remediation(
            text = "Review them under Settings › Security › Device admin apps (the location varies by " +
                "vendor) and deactivate the ones you do not need.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
    )

    override suspend fun run(context: ScanContext): Outcome {
        val admins = policy.activeAdmins()
        val evidence = when (admins) {
            is Reading.Value ->
                if (admins.value.isEmpty()) {
                    listOf(Evidence("Active admins", "none", admins.source))
                } else {
                    admins.value.map { Evidence("Active admin", describe(it), admins.source) }
                }
            else -> listOf(admins.toEvidence("Active admins"))
        }
        return admins.evaluate("Device admins", evidence) { list ->
            if (list.isEmpty()) {
                Outcome.pass("No device admin apps are active", evidence)
            } else {
                val managed = list.any { it.isDeviceOwner }
                val names = list.map { it.app.label }.joinNames()
                val suffix = if (managed) " (the device is managed by an organization)" else ""
                Outcome.fail("${count(list.size, "device admin app")}: $names$suffix", evidence)
            }
        }
    }

    private fun describe(admin: AdminApp): String {
        val role = when {
            admin.isDeviceOwner -> ", device owner"
            admin.isProfileOwner -> ", profile owner"
            else -> ""
        }
        return "${admin.app.label} (${admin.app.packageName}$role)"
    }
}
