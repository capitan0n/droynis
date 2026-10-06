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

/**
 * Android doesn't let apps read whether Google's or the phone maker's find-my-device service is on,
 * so a PASS needs a device admin that declares both the lock and the erase policy and answers to the
 * owner: a known find-my-device service, an app the user installed, or the device owner (MDM). A
 * preinstalled admin outside that list, such as Samsung's Knox Guard financing lock, may answer to
 * the maker, a carrier or a lender, so it never makes a PASS. A known service that may be on is
 * UNKNOWN, never PASS.
 */
class RemoteLockCheck(private val policy: DevicePolicy, private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "ACCS-2020",
        category = Category.ACCESS_CONTROL,
        title = "Remote lock and erase",
        severity = Severity.NOTICE,
        explanation = "If the phone is lost or stolen, a find-my-device service lets you locate, lock and " +
            "erase it from another device. Android doesn't let apps see whether Google's or the phone " +
            "maker's service is turned on, so Droynis looks for an app allowed to lock and erase the " +
            "phone, and for the built-in services it knows.",
        remediation = Remediation(
            text = "Turn on your phone's find-my-device service: with Google services, Settings › Google › " +
                "All services › Find Hub, and Theft protection next to it; on Samsung, Find My Mobile. " +
                "Without Google services, the open-source FMD app (on F-Droid) can locate, lock and erase " +
                "the phone.",
            settingsActions = listOf(SettingsActions.SECURITY),
        ),
        failsWhen = "no app or known service can lock and erase the phone remotely",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val admins = policy.activeAdmins()
        val apps = packages.installedApps()
        val evidence = mutableListOf<Evidence>()

        if (admins !is Reading.Value) {
            evidence += admins.toEvidence("Device admins")
            return Outcome.unknown("The list of device admins could not be read", evidence)
        }
        val installed = (apps as? Reading.Value)?.value?.associateBy { it.packageName }

        // A profile owner's "erase" removes only the work profile, not the phone's data.
        val capable = admins.value.filter { it.canLock == true && it.canWipe == true && (it.isDeviceOwner || !it.isProfileOwner) }
        val yours = capable.filter {
            it.isDeviceOwner || it.app.packageName in KNOWN_SERVICES || installed?.get(it.app.packageName)?.isSystem == false
        }
        val unclear = capable - yours.toSet()
        evidence += if (admins.value.isEmpty()) {
            listOf(Evidence("Device admins", "none", admins.source))
        } else {
            admins.value.map { admin ->
                val owner = if (admin in unclear) "; came with the phone, so it may answer to the maker, a carrier or a lender" else ""
                Evidence("Device admin", "${admin.app.label} (${admin.app.packageName})", admins.source, note = admin.abilities() + owner)
            }
        }
        if (yours.isNotEmpty()) {
            return Outcome.pass("${yours.map { it.app.label }.joinNames()} can lock and erase this phone", evidence)
        }

        if (apps !is Reading.Value) {
            evidence += apps.toEvidence("Installed apps") { "${it.size} apps" }
            return Outcome.unknown("The app list could not be read to look for find-my-device services", evidence)
        }
        val services = KNOWN_SERVICES.filterKeys { pkg -> apps.value.any { it.packageName == pkg && it.isEnabled } }
        services.forEach { (pkg, name) -> evidence += Evidence("Find-my-device service", "$name ($pkg)", apps.source) }
        if (services.isNotEmpty()) {
            return Outcome.unknown(
                "${services.values.toList().joinNames()} can lock and erase a lost phone, but Android doesn't " +
                    "tell apps whether it is turned on",
                evidence,
            )
        }
        if (unclear.isNotEmpty()) {
            return Outcome.unknown(
                "${unclear.map { it.app.label }.joinNames()} can lock and erase this phone, but came with it: " +
                    "Droynis can't tell whether it answers to you",
                evidence,
            )
        }
        val unreadable = admins.value.filter { it.canLock == null || it.canWipe == null }
        if (unreadable.isNotEmpty()) {
            return Outcome.unknown(
                "Could not read what ${unreadable.map { it.app.label }.joinNames()} may do as a device admin",
                evidence,
            )
        }
        return Outcome.fail("Nothing on this phone can lock or erase it remotely", evidence)
    }

    private fun AdminApp.abilities(): String = when {
        canLock == null || canWipe == null -> "its policies could not be read"
        canLock && canWipe -> "may lock and erase the phone"
        canLock -> "may lock the phone"
        canWipe -> "may erase the phone"
        else -> "may neither lock nor erase the phone"
    }

    companion object {
        /**
         * Find-my-device services that may lock and erase a lost phone without showing up as a
         * device admin, so whether they are on stays UNKNOWN. A service missing here counts as absent.
         */
        val KNOWN_SERVICES = linkedMapOf(
            "com.google.android.gms" to "Find Hub (Google Play services)",
            "com.samsung.android.fmm" to "Samsung Find My Mobile",
            "com.xiaomi.finddevice" to "Xiaomi Find device",
            "de.nulide.findmydevice" to "FMD",
        )
    }
}
