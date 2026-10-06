package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.UnknownSourceAppsCheck
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * One "special app access" switch from Settings › Apps › Special app access. Android stores these
 * as app-ops, outside the runtime permissions the base tier can see.
 */
class SpecialAccessCheck(
    private val access: Access,
    private val dumpsys: Dumpsys,
    private val packages: PackageInventory,
) : Check {

    enum class Access(
        val id: String,
        /** App-op name as dumpsys prints it. */
        val op: String,
        /** The switch's name in Settings. */
        val label: String,
        val title: String,
        /** Completes "3 apps …" and "No app …". */
        val phrase: String,
        val explanation: String,
        val remediation: Remediation,
        val minSdk: Int,
        val failsWhen: String,
        /** Apps that need the access to do their job: never a failure. */
        val expected: Set<String> = emptySet(),
        /** INFO for switches worth knowing about that can't hurt much: listed, but not in the score. */
        val severity: Severity = Severity.NOTICE,
    ) {
        OVERLAY(
            id = "APPS-4102",
            op = "SYSTEM_ALERT_WINDOW",
            label = "Display over other apps",
            title = "Apps that can draw over other apps",
            phrase = "can draw over other apps",
            explanation = "Apps allowed to \"Display over other apps\" (on Samsung: \"Appear on top\") can put " +
                "windows on top of anything on the screen. Chat bubbles and screen filters use this; malware uses it to cover real apps " +
                "with fake login forms or to trick you into tapping something else.",
            remediation = Remediation(
                text = "Open Settings › Apps › Special app access › Display over other apps and turn it " +
                    "off for every app listed that doesn't need it. Uninstall apps you don't recognize.",
                settingsActions = listOf(SettingsActions.OVERLAY),
            ),
            minSdk = 29,
            failsWhen = "a user app may display over other apps",
        ),
        ALL_FILES(
            id = "APPS-4103",
            op = "MANAGE_EXTERNAL_STORAGE",
            label = "All files access",
            title = "Apps with access to all files",
            phrase = "can read and change all your files",
            explanation = "\"All files access\" lets an app read, change and delete every file in shared " +
                "storage: photos, downloads and documents, whatever app made them. File managers and " +
                "backup apps need it; most other apps don't.",
            remediation = Remediation(
                text = "Open Settings › Apps › Special app access › All files access and turn it off for " +
                    "every app listed that doesn't manage or back up your files.",
                settingsActions = listOf(SettingsActions.ALL_FILES_ACCESS),
            ),
            minSdk = 30,
            failsWhen = "a user app has all files access",
        ),
        INSTALL_APPS(
            id = "APPS-4104",
            op = "REQUEST_INSTALL_PACKAGES",
            label = "Install unknown apps",
            title = "Apps that can install other apps",
            phrase = "can install other apps",
            explanation = "Apps allowed to \"Install unknown apps\" can offer you APK files to install. You " +
                "still confirm each one, but a malicious or hacked app with this right can push malware " +
                "at you. App stores need it and don't count.",
            remediation = Remediation(
                text = "Open Settings › Apps › Special app access › Install unknown apps and turn it off " +
                    "for the apps listed. Turn it on again only while you install something you trust.",
                settingsActions = listOf(SettingsActions.UNKNOWN_APP_SOURCES),
            ),
            minSdk = 29,
            failsWhen = "a user app other than a known app store may install apps",
            expected = UnknownSourceAppsCheck.KNOWN_STORES,
        ),
        USAGE(
            id = "APPS-4105",
            op = "GET_USAGE_STATS",
            label = "Usage access",
            title = "Apps with usage access",
            phrase = "can see which apps you use",
            explanation = "\"Usage access\" (on Samsung: \"Usage data access\") shows an app which other apps " +
                "you use, when and for how long. " +
                "Launchers and digital wellbeing apps use it; so does stalkerware, to follow what you " +
                "do on the phone.",
            remediation = Remediation(
                text = "Open Settings › Apps › Special app access › Usage access and turn it off for every " +
                    "app listed that doesn't need it.",
                settingsActions = listOf(SettingsActions.USAGE_ACCESS),
            ),
            minSdk = 29,
            failsWhen = "a user app has usage access",
        ),
        WRITE_SETTINGS(
            id = "APPS-4106",
            op = "WRITE_SETTINGS",
            label = "Modify system settings",
            title = "Apps that can change system settings",
            phrase = "can change system settings",
            explanation = "\"Modify system settings\" (on Samsung: \"Change system settings\") lets an app " +
                "change everyday settings such as brightness, ringtone and screen timeout. It can't reach " +
                "security settings, so this check is for your information and doesn't count in the score.",
            remediation = Remediation(
                text = "Open Settings › Apps › Special app access › Modify system settings and turn it off " +
                    "for apps you don't expect there.",
                settingsActions = listOf(SettingsActions.WRITE_SETTINGS),
            ),
            minSdk = 29,
            failsWhen = "a user app may change system settings (information only)",
            severity = Severity.INFO,
        ),
        MANAGE_MEDIA(
            id = "APPS-4107",
            op = "MANAGE_MEDIA",
            label = "Media management apps",
            title = "Apps that can manage your media",
            phrase = "can change or delete photos and videos without asking",
            explanation = "\"Media management\" (on Samsung: \"Manage media\") lets an app that can see your " +
                "photos, videos and audio also change, move or delete them without asking you each time. " +
                "Gallery apps use it. This check is for your information and doesn't count in the score.",
            remediation = Remediation(
                text = "Open Settings › Apps › Special app access › Media management apps and turn it off " +
                    "for apps that don't organize your media.",
                settingsActions = listOf(SettingsActions.MANAGE_MEDIA),
            ),
            minSdk = 31,
            failsWhen = "a user app may change or delete media without asking (information only)",
            severity = Severity.INFO,
        ),
    }

    override val spec = CheckSpec(
        id = access.id,
        category = Category.APPS,
        title = access.title,
        severity = access.severity,
        explanation = access.explanation + " Android keeps this switch in its app-ops service, which only " +
            "the ADB or Shizuku tier can read.",
        remediation = access.remediation,
        // The dump's op lines have this shape from Android 10; older output is not parsed.
        minSdk = access.minSdk,
        requires = setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS),
        timeout = 15.seconds,
        failsWhen = access.failsWhen,
    )

    override suspend fun run(context: ScanContext): Outcome {
        val dump = when (val reading = dumpsys.dump(BackgroundSensorUseCheck.SERVICE)) {
            is Reading.Value -> reading
            is Reading.Unsupported -> return Outcome.unsupported(
                "The app-ops service is not available (${reading.reason})",
                listOf(reading.toEvidence("App-op modes")),
            )
            is Reading.Unavailable -> return Outcome.unknown(
                "App-op modes could not be read (${reading.reason})",
                listOf(reading.toEvidence("App-op modes")),
            )
        }
        val source = dump.source
        val parsed = when (val result = AppOpModes.allowed(dump.value, setOf(access.op))) {
            is AppOpModes.Result.Failed -> return Outcome.unknown(
                "App-op modes are in a format Droynis doesn't recognize (${result.reason})",
                listOf(Evidence("App-op modes", null, source, note = result.reason)),
            )
            is AppOpModes.Result.Parsed -> result
        }
        val checked = Evidence("Apps inspected", "${count(parsed.packages, "app")} with app-op records", source)
        if (parsed.grants.isEmpty()) return Outcome.pass("No app ${access.phrase}", listOf(checked))

        // Only now are system apps worth telling apart; without the app list that is impossible.
        val installed = when (val apps = packages.installedApps()) {
            is Reading.Value -> apps.value
            else -> return Outcome.unknown(
                "Some apps ${access.phrase}, but the app list to tell system apps apart could not be read",
                listOf(checked, apps.toEvidence("Installed apps") { "${it.size} apps" }),
            )
        }
        val byPackage = installed.associateBy { it.packageName }
        val byUid = installed.filter { it.uid != null }.groupBy { it.uid }

        // A uid-wide grant with no package in the dump still names the app through its uid.
        val holders = parsed.grants.flatMap { grant ->
            val named = grant.packageName?.let(::listOf)
                ?: AppOpModes.uidOf(grant.uid)?.let { uid -> byUid[uid]?.map { it.packageName } }
            named.orEmpty().ifEmpty { listOf(null) }.map { it to grant }
        }.distinctBy { it.first ?: it.second.uid }

        val own = holders.filter { it.first != null && it.first == context.appPackage }
        val expected = holders.filter { it.first in access.expected }
        val system = holders.filter { (pkg, _) -> pkg != null && byPackage[pkg]?.isSystem == true }
        // Packages missing from the list (another user's apps, an unknown uid) count as user apps: never hide them.
        val flagged = holders - own.toSet() - expected.toSet() - system.toSet()

        val evidence = buildList {
            add(checked)
            flagged.forEach { (pkg, grant) -> add(holderEvidence(pkg, grant, source, note = modeNote(grant))) }
            expected.forEach { (pkg, grant) -> add(holderEvidence(pkg, grant, source, note = "an app store; not counted")) }
            own.forEach { (pkg, grant) -> add(holderEvidence(pkg, grant, source, note = "Droynis itself; not counted")) }
            if (system.isNotEmpty()) add(Evidence("System apps allowed", system.size.toString(), source))
        }
        if (flagged.isEmpty()) return Outcome.pass("No user app ${access.phrase}", evidence)

        val names = flagged.map { (pkg, grant) -> pkg?.let(packages::label) ?: "an app with uid ${grant.uid}" }.distinct()
        return Outcome.fail("${count(names.size, "app")} ${access.phrase}: ${names.joinNames()}", evidence)
    }

    private fun holderEvidence(pkg: String?, grant: OpGrant, source: Source, note: String?) =
        Evidence(
            access.label,
            pkg?.let { "${packages.label(it)} ($it)" } ?: "unknown app (uid ${grant.uid})",
            source,
            note = note,
        )

    private fun modeNote(grant: OpGrant): String? =
        if (grant.mode == "foreground") "only while the app is in use" else null
}
