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
import io.github.capitan0n.droynis.core.Trust
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * Apps whose installer of record is another installed app rather than an app store or Android's
 * package installer: how a dropper delivers its payload past store review.
 */
class InstalledByAppCheck(private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5004",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps installed by another app",
        severity = Severity.WARNING,
        explanation = "Malware often arrives in two steps: a harmless-looking app, the dropper, later installs the " +
            "real payload itself, so no app store reviews it. Android records which app installed each app. " +
            "Droynis lists apps installed by another app you installed, rather than by an app store or Android's " +
            "own package installer. Installer tools such as SAI and App Manager, and apps that update themselves, " +
            "are left out.",
        remediation = Remediation(
            text = "For each app listed, check that you asked the installing app to install it. If you didn't, " +
                "uninstall both. If you use an app store Droynis doesn't know, trust it: the apps it installed then " +
                "stop counting.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an app was installed by another app you installed that isn't an app store or an installer tool",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        if (apps !is Reading.Value) {
            return Outcome.unknown("Could not read the installed apps", listOf(apps.toEvidence("Installed apps")))
        }
        val inventory = apps.value.associateBy { it.packageName }
        val user = apps.value.filter { !it.isSystem && it.isEnabled }
        val evidence = mutableListOf(Evidence("User apps inspected", user.size.toString(), apps.source))

        val found = user.mapNotNull { app ->
            val installer = app.installer ?: return@mapNotNull null
            if (!isOtherApp(app.packageName, installer, inventory)) return@mapNotNull null
            Found(app.packageName, installer, installerGone = installer !in inventory)
        }
        if (found.isEmpty()) return Outcome.pass(NONE, evidence)

        // The user can trust the installed app, or the installer (an app store Droynis doesn't know).
        val trusted = found.filter { context.trusts(it.packageName) || context.trusts(it.installer) }
        val counted = found - trusted.toSet()
        evidence += found.map { item ->
            val isTrusted = item in trusted
            val installerName = if (item.installerGone) {
                "${item.installer}, which is no longer installed"
            } else {
                "${packages.label(item.installer)} (${item.installer})"
            }
            Evidence(
                "Installed by",
                "${packages.label(item.packageName)} (${item.packageName})",
                apps.source,
                note = withTrustNote("installed by $installerName", isTrusted),
                packageName = item.packageName,
                trust = if (isTrusted) Trust.TRUSTED else Trust.COUNTED,
            )
        }
        if (counted.isEmpty()) {
            return Outcome.pass(onlyTrusted("were installed by another app", trusted.map { packages.label(it.packageName) }), evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} installed by another app: ${counted.map { packages.label(it.packageName) }.joinNames()}",
            evidence,
        )
    }

    private data class Found(val packageName: String, val installer: String, val installerGone: Boolean)

    internal companion object {
        const val NONE = "No app was installed by another app you installed"

        /**
         * Apps that install APKs the user picked, the way the package installer does: what they
         * install is sideloaded (APPS-4004 lists it), not dropped.
         */
        val INSTALLER_TOOLS = setOf(
            "com.aefyr.sai", // SAI (Split APKs Installer)
            "com.aefyr.sai.fdroid",
            "io.github.muntashirakon.AppManager", // App Manager
            "com.rosan.installer.x", // InstallerX
            "com.apkmirror.helper.prod", // APKMirror Installer
        )

        /**
         * [installer] is another app the user installed: not the app itself (self-updates), not an
         * app store or installer tool, and not part of the system (the package installer, the shell
         * for adb, a vendor's store). An installer missing from the list counts: a dropper can remove
         * itself once its payload is in.
         */
        fun isOtherApp(packageName: String, installer: String, inventory: Map<String, InstalledApp>): Boolean =
            installer != packageName &&
                installer !in UnknownSourceAppsCheck.KNOWN_STORES &&
                installer !in UnknownSourceAppsCheck.OS_INSTALLERS &&
                installer !in INSTALLER_TOOLS &&
                inventory[installer]?.isSystem != true
    }
}
