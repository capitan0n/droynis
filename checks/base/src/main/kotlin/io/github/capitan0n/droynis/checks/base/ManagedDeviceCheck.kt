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
import io.github.capitan0n.droynis.core.toEvidence

/**
 * Whether someone else manages this phone: a device owner, a profile owner of the user Droynis runs
 * in, or an organization that owns the phone and manages its work profile
 * (`DevicePolicyManager.isOrganizationOwnedDeviceWithManagedProfile()`, which answers any app from
 * Android 11). APPS-4002 counts owners among the device admins; this check says what an owner means
 * for everything else the scan reports. The owner of a work profile on a phone you own yourself is
 * not visible from the personal side: APPS-4017 reports that profile.
 */
class ManagedDeviceCheck(
    private val policy: DevicePolicy,
    private val profiles: ProfileProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "INTG-1031",
        category = Category.DEVICE_INTEGRITY,
        title = "Managed by an organization",
        severity = Severity.INFO,
        explanation = "A device owner controls the whole phone: it can install and remove apps, read which " +
            "apps you use, route your traffic, add certificates and erase everything, and settings it locks " +
            "can't be changed by you. A profile owner has the same reach inside its profile. An employer or " +
            "school sets this up on phones it hands out; on a phone you bought yourself, an owner set up " +
            "from a computer with adb is how some monitoring apps take control. This check is for your " +
            "information and doesn't count in the score, unless the owner came from outside an app store.",
        remediation = Remediation(
            text = "If the phone belongs to your employer or school, this is expected: ask them what they " +
                "can see. If it is your own phone and you don't recognize the app, back up your data and " +
                "erase the phone (factory reset): an owner can't be removed like an ordinary app.",
            settingsActions = listOf(SettingsActions.DEVICE_ADMINS, SettingsActions.SECURITY),
        ),
        failsWhen = "a device or profile owner manages this user, or an organization owns the phone " +
            "(information only; a warning when the owner came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val admins = policy.activeAdmins()
        val organization = profiles.organizationOwned()
        val organizationEvidence = organization.toEvidence("Owned by an organization, with a work profile") { if (it) "yes" else "no" }
        if (admins !is Reading.Value) {
            val evidence = listOf(admins.toEvidence("Active admins"), organizationEvidence)
            // An organization-owned phone is managed whatever the admin list says.
            if ((organization as? Reading.Value)?.value == true) return Outcome.fail(ORGANIZATION_OWNED, evidence)
            return when (admins) {
                is Reading.Unsupported -> Outcome.unsupported("Device admins are not available on this device (${admins.reason})", evidence)
                else -> Outcome.unknown("Could not read who manages this phone", evidence)
            }
        }

        val inventory = packages.byPackage()
        val owners = admins.value.filter { it.isDeviceOwner || it.isProfileOwner }
        val holders = owners.associateWith { Holder(it.app, originOf(it.app.packageName, inventory)) }
        val (trusted, counted) = context.splitTrusted(owners) { it.app.packageName }
        val evidence = owners.map {
            val label = if (it.isDeviceOwner) "Device owner" else "Profile owner"
            holders.getValue(it).evidence(label, admins.source, trusted = it in trusted)
        } + organizationEvidence

        val organizationOwned = (organization as? Reading.Value)?.value == true
        if (counted.isEmpty() && !organizationOwned) {
            return when {
                trusted.isNotEmpty() ->
                    Outcome.pass(onlyTrusted("manage this phone", trusted.map { it.app.label }), evidence)
                // "Not organization-owned" was not read: never a PASS on half the answer.
                organization is Reading.Unavailable ->
                    Outcome.unknown("No device or profile owner is active, but whether an organization owns the phone could not be read", evidence)
                else -> Outcome.pass("No device or profile owner manages this user", evidence)
            }
        }
        if (counted.isEmpty()) return Outcome.fail(ORGANIZATION_OWNED, evidence)

        val device = counted.filter { it.isDeviceOwner }
        val summary = if (device.isNotEmpty()) {
            "${device.map { it.app.label }.joinNames()} manages the whole phone as its device owner"
        } else {
            "${counted.map { it.app.label }.joinNames()} ${if (counted.size == 1) "manages" else "manage"} this profile as its owner"
        }
        val countedHolders = counted.map { holders.getValue(it) }
        return Outcome.fail(summary + sideloadedSuffix(countedHolders), evidence, escalation = sideloadedEscalation(countedHolders))
    }

    private companion object {
        const val ORGANIZATION_OWNED = "An organization owns this phone and manages its work profile"
    }
}
