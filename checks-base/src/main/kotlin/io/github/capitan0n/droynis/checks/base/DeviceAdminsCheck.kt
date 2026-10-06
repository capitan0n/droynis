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

class DeviceAdminsCheck(
    private val policy: DevicePolicy,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4002",
        category = Category.APPS,
        title = "Device admin apps",
        severity = Severity.NOTICE,
        explanation = "Device admin apps can lock or wipe the phone and enforce password rules; a device " +
            "or profile owner can manage it completely. Find-my-device and work profiles use this " +
            "legitimately; anything you do not recognize deserves a closer look, and one installed from " +
            "outside an app store is a warning. Admins that came with the phone are listed but don't " +
            "count, unless they own the device.",
        remediation = Remediation(
            text = "Review them under Settings › Security › Device admin apps (the location varies by " +
                "vendor) and deactivate the ones you do not need.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        failsWhen = "a device admin you installed, or a device or profile owner, is active (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val admins = policy.activeAdmins()
        return admins.evaluate("Device admins", listOf(admins.toEvidence("Active admins"))) { list ->
            if (list.isEmpty()) {
                return@evaluate Outcome.pass("No device admin apps are active", listOf(Evidence("Active admins", "none", admins.source)))
            }
            val inventory = packages.byPackage()
            val origins = list.associateWith { originOf(it.app.packageName, inventory) }
            // An owner manages the device whatever its origin; other preinstalled admins are part of the phone.
            val counted = list.filter { it.isDeviceOwner || it.isProfileOwner || origins.getValue(it) != AppOrigin.PREINSTALLED }
            val evidence = list.map { admin ->
                val note = origins.getValue(admin).note + if (admin in counted) "" else "; not counted"
                Evidence("Active admin", describe(admin), admins.source, note = note)
            }
            if (counted.isEmpty()) return@evaluate Outcome.pass("Only device admins that came with the phone are active", evidence)
            val holders = counted.map { Holder(it.app, origins.getValue(it)) }
            val suffix = if (counted.any { it.isDeviceOwner }) " (the device is managed by an organization)" else ""
            Outcome.fail(
                "${count(counted.size, "device admin app")}: ${holders.map { it.app.label }.joinNames()}$suffix" +
                    sideloadedSuffix(holders),
                evidence,
                escalation = sideloadedEscalation(holders),
            )
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
