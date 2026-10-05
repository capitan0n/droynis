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
        val sideloaded = (apps as? Reading.Value)?.value
            ?.filter { !it.isSystem && it.installer !in KNOWN_STORES }
            .orEmpty()
        val evidence = buildList {
            add(apps.toEvidence("User apps inspected") { list -> list.count { !it.isSystem }.toString() })
            sideloaded.forEach {
                add(Evidence("Installed by", "${packages.label(it.packageName)}: ${it.installer ?: "unknown (adb or file)"}", apps.source))
            }
        }
        return apps.evaluate("Installed apps", evidence) {
            if (sideloaded.isEmpty()) {
                Outcome.pass("Every app came from a known app store", evidence)
            } else {
                val names = sideloaded.map { packages.label(it.packageName) }.joinNames()
                Outcome.fail("${count(sideloaded.size, "app")} from outside an app store: $names", evidence)
            }
        }
    }

    companion object {
        /** Installer packages of app stores and FOSS updaters treated as known sources. */
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
        )
    }
}
