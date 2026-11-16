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
import kotlin.time.Duration.Companion.seconds

class UnknownSourceAppsCheck(private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "APPS-4004",
        category = Category.APPS,
        title = "Apps from unknown sources",
        severity = Severity.NOTICE,
        explanation = "Apps installed from a downloaded file or over adb skip the review an app store " +
            "performs and usually do not update automatically. That is fine for apps you trust, but each " +
            "one is worth knowing about.",
        remediation = Remediation(
            text = "Review the list and uninstall apps you do not recognize. Prefer a store such as " +
                "F-Droid, Accrescent or Google Play, which also keeps the apps updated.",
            settingsActions = listOf(SettingsActions.APPS, SettingsActions.UNKNOWN_APP_SOURCES),
        ),
        timeout = 15.seconds,
        failsWhen = "an app came from outside a known app store",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        val all = (apps as? Reading.Value)?.value
        val byPackage = all?.associateBy { it.packageName }
        val outside = all
            ?.filter { originOf(it.packageName, byPackage) == AppOrigin.SIDELOADED }
            .orEmpty()
        val (trusted, sideloaded) = context.splitTrusted(outside) { it.packageName }
        val evidence = buildList {
            add(apps.toEvidence("User apps inspected") { list -> list.count { !it.isSystem }.toString() })
            outside.forEach {
                val isTrusted = it in trusted
                add(
                    Evidence(
                        "From outside an app store",
                        "${packages.label(it.packageName)} (${it.packageName})",
                        apps.source,
                        note = withTrustNote(installedBy(it, byPackage.orEmpty()), isTrusted),
                        packageName = it.packageName,
                        trust = trustOf(counted = true, trusted = isTrusted),
                    ),
                )
            }
        }
        return apps.evaluate("Installed apps", evidence) {
            if (sideloaded.isEmpty() && trusted.isNotEmpty()) {
                Outcome.pass(onlyTrusted("come from outside an app store", trusted.map { packages.label(it.packageName) }), evidence)
            } else if (sideloaded.isEmpty()) {
                Outcome.pass("Every app came from a known app store", evidence)
            } else {
                val names = sideloaded.map { packages.label(it.packageName) }.joinNames()
                Outcome.fail("${count(sideloaded.size, "app")} from outside an app store: $names", evidence)
            }
        }
    }

    /** Who installed [app], in words: the app is the evidence's value, so this is its note. */
    private fun installedBy(app: InstalledApp, inventory: Map<String, InstalledApp>): String {
        val installer = app.installer
        return when {
            installer == null -> "installed from a file or over adb"
            installer == app.packageName -> "installed and updated by itself"
            StoreKeys.isImpostor(installer, inventory) ->
                "installed by ${packages.label(installer)} ($installer), which uses an app store's name without its signing key"
            installer in inventory -> "installed by ${packages.label(installer)} ($installer)"
            else -> "installed by $installer, which is not installed"
        }
    }

    companion object {
        /**
         * Installer packages of app stores and FOSS updaters treated as known sources. Each has an
         * entry in [StoreKeys]: a user-installed copy counts only when its signing key checks out.
         */
        val KNOWN_STORES = setOf(
            "com.android.vending", // Google Play
            "org.fdroid.fdroid", // F-Droid
            "org.fdroid.basic", // F-Droid Basic
            "com.machiav3lli.fdroid", // Neo Store
            "com.looker.droidify", // Droid-ify
            "app.accrescent.client", // Accrescent
            "com.aurora.store", // Aurora Store
            "dev.imranr.obtainium", // Obtainium
            "com.sec.android.app.samsungapps", // Galaxy Store
            "com.huawei.appmarket", // AppGallery
            "com.amazon.venezia", // Amazon Appstore
            "com.xiaomi.mipicks", // Xiaomi GetApps
            "com.xiaomi.market", // Xiaomi App Store
            "com.heytap.market", // OPPO, OnePlus and realme App Market
            "com.vivo.appstore", // vivo App Store
            "com.bbk.appstore", // vivo App Store, older name
            "foundation.e.apps", // App Lounge (/e/OS)
        )

        /**
         * A phone maker's companion apps that fetch their own plug-ins, and their own updates, from
         * that maker's store servers and install them themselves. What they install counts as coming
         * from an app store. They are no general app store, so APPS-4104 still counts them.
         */
        val PLUGIN_INSTALLERS = setOf(
            "com.samsung.android.app.watchmanager", // Galaxy Wearable: watch and earbuds plug-ins
        )

        /** Every installer whose apps count as coming from an app store. */
        fun isStoreInstaller(installer: String?): Boolean = installer in KNOWN_STORES || installer in PLUGIN_INSTALLERS

        /**
         * System apps that install apps shipped with the OS as removable user apps. Their apps came
         * with the phone; an app using one of these names without being a system app counts for nothing.
         */
        val OS_INSTALLERS = setOf(
            "foundation.e.apk_preinstaller", // /e/OS
        )
    }
}
