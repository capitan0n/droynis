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

class OutdatedAppsCheck(private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "APPS-4007",
        category = Category.APPS,
        title = "Apps built for old Android",
        severity = Severity.NOTICE,
        explanation = "Android applies many protections only to apps that declare a recent target version, " +
            "for example scoped storage and limits on reading device identifiers. Apps built for Android 8.1 " +
            "or older skip them and are usually no longer maintained; Android 14 even refuses to install apps " +
            "built for Android 5.1 or older.",
        remediation = Remediation(
            text = "Update these apps, or replace the ones that are no longer maintained.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "a user app targets Android 8.1 (API 27) or older",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        val old = (apps as? Reading.Value)?.value
            ?.filter { !it.isSystem && it.targetSdk < MIN_TARGET_SDK }
            .orEmpty()
        val evidence = buildList {
            add(apps.toEvidence("User apps inspected") { list -> list.count { !it.isSystem }.toString() })
            old.forEach {
                add(Evidence("Targets API ${it.targetSdk}", "${packages.label(it.packageName)} (${it.packageName})", apps.source))
            }
        }
        return apps.evaluate("Installed apps", evidence) {
            if (old.isEmpty()) {
                Outcome.pass("Every installed app targets Android 9 or newer", evidence)
            } else {
                val names = old.map { packages.label(it.packageName) }.joinNames()
                Outcome.fail("${count(old.size, "app")} built for Android 8.1 or older: $names", evidence)
            }
        }
    }

    companion object {
        /** Android 9 (API 28). */
        const val MIN_TARGET_SDK = 28
    }
}
