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
import kotlin.time.Duration.Companion.seconds

/**
 * Apps that turned their app drawer icon off, or show a blank name or a transparent icon. Critical
 * when such an app also came from outside an app store, or holds the access stalkerware and banking
 * trojans rely on: accessibility, device admin or notification access.
 */
class HiddenAppsCheck(
    private val footprints: AppFootprintProbe,
    private val packages: PackageInventory,
    private val accessibility: AccessibilityProbe,
    private val policy: DevicePolicy,
    private val settings: SystemSettings,
) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5001",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps hiding from the app drawer",
        severity = Severity.WARNING,
        explanation = "Adware and stalkerware hide after their first start, so you can't find them to remove " +
            "them: they turn their app drawer icon off, or keep it but give it a blank name and a transparent " +
            "icon. Since Android 10 an app that turns its icon off usually still gets a placeholder that opens " +
            "App info, which is why hiding apps now use the blank name and transparent icon. A hiding app with " +
            "accessibility, device admin or notification access is how stalkerware and banking trojans are set " +
            "up. A few legitimate apps hide too, such as anti-theft apps, so check whether you installed each " +
            "one on purpose.",
        remediation = Remediation(
            text = "Open each app listed (the button next to it opens its App info) and uninstall it unless you " +
                "know why it hides. If Uninstall is greyed out, the app is a device admin: remove it under " +
                "Security › Device admin apps first. An app with a blank name is listed here by its package name.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        // Draws every user app's icon once; a phone with a few hundred apps needs a few seconds.
        timeout = 30.seconds,
        failsWhen = "an installed app turned its app drawer icon off, or shows a blank name or a transparent icon " +
            "(critical when it came from outside an app store, or has accessibility, device admin or notification access)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = readSightings(footprints, packages) { return it }
        val hiding = context.judge(apps.all.filter { it.hiding })
        val evidence = mutableListOf(apps.inspected())
        if (hiding.all.isEmpty()) return Outcome.pass("No installed app hides from the app drawer", evidence)

        // Only read when something hides: each access is a separate read.
        val accesses = Access.entries.associateWith { read(it) }
        accesses.values.filter { it !is Reading.Value }.forEach { evidence += it.toEvidence("Access") }
        val held = hiding.all.associateWith { app ->
            Access.entries.filter { (accesses.getValue(it) as? Reading.Value)?.value?.contains(app.packageName) == true }
        }

        evidence += hiding.all.map { app ->
            val details = held.getValue(app).joinToString(", ") { it.note }.ifEmpty { null }
            app.evidence("Hiding", apps.source, details, trusted = hiding.isTrusted(app))
        }
        if (hiding.counted.isEmpty()) {
            return Outcome.pass(
                hiding.passSummary("No installed app hides from the app drawer", "hide from the app drawer", subject = "apps"),
                evidence,
            )
        }
        val powerful = hiding.counted.any { held.getValue(it).isNotEmpty() }
        return Outcome.fail(
            "${count(hiding.counted.size, "app")} hiding from the app drawer: ${hiding.counted.names()}",
            evidence,
            escalation = if (powerful) Severity.CRITICAL else hiding.counted.escalation(),
        )
    }

    /** Package names holding [access]; a reading without a value never escalates. */
    private fun read(access: Access): Reading<Set<String>> = when (access) {
        Access.ACCESSIBILITY -> accessibility.enabledServices().map { apps -> apps.mapTo(HashSet()) { it.packageName } }
        Access.DEVICE_ADMIN -> policy.activeAdmins().map { admins -> admins.mapTo(HashSet()) { it.app.packageName } }
        Access.NOTIFICATIONS -> settings.secure(NotificationAccessCheck.ENABLED_NOTIFICATION_LISTENERS)
            .map { NotificationAccessCheck.listenerPackages(it).toSet() }
    }

    internal enum class Access(val note: String) {
        ACCESSIBILITY("has accessibility access"),
        DEVICE_ADMIN("is a device admin"),
        NOTIFICATIONS("can read your notifications"),
    }
}

/** The reading's value transformed by [transform], keeping its source; failures pass through. */
internal inline fun <T, R> Reading<T>.map(transform: (T) -> R): Reading<R> = when (this) {
    is Reading.Value -> Reading.Value(transform(value), source)
    is Reading.Unsupported -> this
    is Reading.Unavailable -> this
}
