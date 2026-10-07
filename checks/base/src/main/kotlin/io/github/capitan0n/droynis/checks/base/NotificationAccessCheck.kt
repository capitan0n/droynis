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
import io.github.capitan0n.droynis.core.evaluate

class NotificationAccessCheck(
    private val settings: SystemSettings,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4005",
        category = Category.APPS,
        title = "Notification access",
        severity = Severity.NOTICE,
        explanation = "An app with notification access reads every notification as it arrives, including " +
            "message previews and one-time login codes sent by SMS, and can act on them. Watch and automation apps " +
            "need it; any other app that has it deserves a second look, and one installed from outside " +
            "an app store is a warning. Apps that came with the phone, like the launcher's badges, are " +
            "listed but don't count.",
        remediation = Remediation(
            text = "Under Special app access › Notification access (the name varies by vendor), turn it off " +
                "for apps that do not need it.",
            settingsActions = listOf(SettingsActions.NOTIFICATION_ACCESS),
        ),
        failsWhen = "an app you installed can read all notifications (a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        // Hidden but @Readable; AndroidX NotificationManagerCompat reads the same key.
        val setting = settings.secure(ENABLED_NOTIFICATION_LISTENERS)
        val listeners: Reading<List<AppRef>> = when (setting) {
            is Reading.Value -> Reading.Value(
                listenerPackages(setting.value).map { AppRef(it, packages.label(it)) },
                setting.source,
            )
            is Reading.Unsupported -> setting
            is Reading.Unavailable -> setting
        }
        return listeners.evaluate("Notification access", appEvidence("Notification listeners", listeners)) { apps ->
            if (apps.isEmpty()) {
                return@evaluate Outcome.pass("No app can read your notifications", appEvidence("Notification listeners", listeners))
            }
            // Apps that came with the phone, such as the launcher showing badges, are part of the system.
            val all = holders(apps, packages.byPackage())
            val counted = all.filter { it.origin != AppOrigin.PREINSTALLED }
            val evidence = all.map { it.evidence("Notification listener", listeners.source, counted = it in counted) }
            if (counted.isEmpty()) {
                return@evaluate Outcome.pass("Only apps that came with the phone can read your notifications", evidence)
            }
            Outcome.fail(
                "${count(counted.size, "app")} can read your notifications: ${counted.map { it.app.label }.joinNames()}" +
                    sideloadedSuffix(counted),
                evidence,
                escalation = sideloadedEscalation(counted),
            )
        }
    }

    companion object {
        /** `Settings.Secure.ENABLED_NOTIFICATION_LISTENERS` (hidden, readable) */
        const val ENABLED_NOTIFICATION_LISTENERS = "enabled_notification_listeners"

        /** "pkg/cls:pkg2/.Cls" (flattened component names) to distinct package names. */
        internal fun listenerPackages(raw: String?): List<String> =
            raw.orEmpty().split(':')
                .map { it.substringBefore('/').trim() }
                .filter { it.isNotEmpty() }
                .distinct()
    }
}
