package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import kotlin.time.Duration.Companion.seconds

/** Apps that turned their app drawer icon off, or show a blank name or a transparent icon. */
class HiddenAppsCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5001",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps hiding from the app drawer",
        severity = Severity.WARNING,
        explanation = "Adware and stalkerware hide after their first start, so you can't find them to remove " +
            "them: they turn their app drawer icon off, or keep it but give it a blank name and a transparent " +
            "icon. Since Android 10 an app that turns its icon off usually still gets a placeholder that opens " +
            "App info, which is why hiding apps now use the blank name and transparent icon. A few legitimate " +
            "apps hide too, such as anti-theft apps, so check whether you installed each one on purpose.",
        remediation = Remediation(
            text = "Open each app listed (the button next to it opens its App info) and uninstall it unless you " +
                "know why it hides. If Uninstall is greyed out, the app is a device admin: remove it under " +
                "Security › Device admin apps first. An app with a blank name is listed here by its package name.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        // Draws every user app's icon once; a phone with a few hundred apps needs a few seconds.
        timeout = 30.seconds,
        failsWhen = "an installed app turned its app drawer icon off, or shows a blank name or a transparent icon " +
            "(critical when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = readSightings(footprints, packages) { return it }
        val hiding = context.judge(apps.all.filter { it.hiding })
        val evidence = listOf(apps.inspected()) +
            hiding.all.map { it.evidence("Hiding", apps.source, trusted = hiding.isTrusted(it)) }
        if (hiding.counted.isEmpty()) {
            return Outcome.pass(
                hiding.passSummary("No installed app hides from the app drawer", "hide from the app drawer", subject = "apps"),
                evidence,
            )
        }
        return Outcome.fail(
            "${count(hiding.counted.size, "app")} hiding from the app drawer: ${hiding.counted.names()}",
            evidence,
            escalation = hiding.counted.escalation(),
        )
    }
}
