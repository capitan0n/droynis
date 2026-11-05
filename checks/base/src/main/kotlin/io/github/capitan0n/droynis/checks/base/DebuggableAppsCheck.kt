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

class DebuggableAppsCheck(private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "APPS-4003",
        category = Category.APPS,
        title = "Debuggable apps",
        severity = Severity.WARNING,
        explanation = "A debuggable app lets anyone with adb access read its private data and run code " +
            "inside it. Store builds are never debuggable, so a debuggable app is a development build or " +
            "has been modified.",
        remediation = Remediation(
            text = "Uninstall debuggable apps you are not developing yourself, or replace them with the " +
                "official release. Droynis itself is excluded from this check.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an installed app is debuggable",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        val all = (apps as? Reading.Value)?.value?.filter { it.isDebuggable }.orEmpty()
        val (trusted, debuggable) = context.splitTrusted(all) { it.packageName }
        val evidence = buildList {
            add(apps.toEvidence("Apps inspected") { it.size.toString() })
            all.forEach {
                val isTrusted = it in trusted
                add(
                    Evidence(
                        "Debuggable",
                        "${packages.label(it.packageName)} (${it.packageName})",
                        apps.source,
                        note = withTrustNote(null, isTrusted),
                        packageName = it.packageName,
                        trust = trustOf(counted = true, trusted = isTrusted),
                    ),
                )
            }
        }
        return apps.evaluate("Installed apps", evidence) {
            if (debuggable.isEmpty() && trusted.isNotEmpty()) {
                Outcome.pass(onlyTrusted("are debuggable", trusted.map { packages.label(it.packageName) }), evidence)
            } else if (debuggable.isEmpty()) {
                Outcome.pass("No debuggable apps are installed", evidence)
            } else {
                val names = debuggable.map { packages.label(it.packageName) }.joinNames()
                Outcome.fail("${count(debuggable.size, "debuggable app")}: $names", evidence)
            }
        }
    }
}
