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
            "message previews and one-time login codes, and can act on them. Watch and automation apps " +
            "need it; any other app that has it deserves a second look.",
        remediation = Remediation(
            text = "Under Special app access › Notification access (the name varies by vendor), turn it off " +
                "for apps that do not need it.",
            settingsActions = listOf(SettingsActions.NOTIFICATION_ACCESS),
        ),
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
        val evidence = appEvidence("Notification listeners", listeners)
        return listeners.evaluate("Notification access", evidence) { apps ->
            if (apps.isEmpty()) {
                Outcome.pass("No app can read your notifications", evidence)
            } else {
                Outcome.fail(
                    "${count(apps.size, "app")} can read your notifications: ${apps.map { it.label }.joinNames()}",
                    evidence,
                )
            }
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
