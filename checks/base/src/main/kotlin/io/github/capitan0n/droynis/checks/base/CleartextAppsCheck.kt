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
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/**
 * User apps whose manifest allows unencrypted traffic (`ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC`)
 * and that hold INTERNET. The flag is what the app declares, or Android's default for apps built for
 * Android 8.1 or older; Android ignores it when the app ships a network security config, which no
 * other app can read. So this is a sign, never proof, in either direction.
 */
class CleartextAppsCheck(
    private val packages: PackageInventory,
    private val permissions: PermissionProbe,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4018",
        category = Category.APPS,
        title = "Apps that allow unencrypted connections",
        severity = Severity.INFO,
        explanation = "An app that allows cleartext traffic may send data over plain HTTP, which anyone on " +
            "the same Wi-Fi or along the way can read and change. Browsers and apps that talk to devices on " +
            "your home network need it; most other apps don't. Droynis reads only what each app declares: an " +
            "app can narrow or widen it in a network security config that other apps can't see, and " +
            "allowing it doesn't mean the app uses it. Apps that came with the phone aren't listed. This " +
            "check is for your information and doesn't count in the score.",
        remediation = Remediation(
            text = "Nothing to change in Settings: only the app's developer can turn this off. On networks " +
                "you don't control, use a VPN, and prefer apps that don't allow it for anything sensitive.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "an app you installed has network access and declares that it may connect without encryption (information only)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        if (apps !is Reading.Value) {
            return Outcome.unknown("Could not read the installed apps", listOf(apps.toEvidence("Installed apps")))
        }
        val user = apps.value.filter { !it.isSystem }
        val inspected = Evidence("User apps inspected", user.size.toString(), apps.source)
        val declaring = user.filter { it.usesCleartextTraffic }
        if (declaring.isEmpty()) return Outcome.pass(NONE, listOf(inspected))

        // Without INTERNET an app can't open a connection at all, whatever it declares.
        val online = permissions.holders(setOf(INTERNET))
        if (online !is Reading.Value) {
            return Outcome.unknown(
                "${count(declaring.size, "app allows", "apps allow")} unencrypted connections, but which of " +
                    "them have network access could not be read",
                listOf(inspected, online.toEvidence("Network access")),
            )
        }
        val inventory = apps.value.associateBy { it.packageName }
        val listed = declaring.filter { it.packageName in online.value }
            .map { Holder(AppRef(it.packageName, packages.label(it.packageName)), originOf(it.packageName, inventory)) }
            .sortedBy { it.app.label.lowercase() }
        val (trusted, holders) = context.splitTrusted(listed) { it.app.packageName }
        val evidence = listOf(inspected) +
            listed.map { it.evidence("Allows unencrypted connections", apps.source, trusted = it in trusted) }
        if (holders.isEmpty() && trusted.isNotEmpty()) {
            return Outcome.pass(onlyTrusted("allow unencrypted connections", trusted.labels()), evidence)
        }
        if (holders.isEmpty()) return Outcome.pass(NONE, evidence)

        // Information only: a sideloaded app is named, but never raises the severity.
        return Outcome.fail(
            "${count(holders.size, "app")} may connect without encryption: " +
                holders.map { it.app.label }.joinNames() + sideloadedSuffix(holders),
            evidence,
        )
    }

    companion object {
        const val INTERNET = "android.permission.INTERNET"
        private const val NONE = "No app you installed with network access allows unencrypted connections"
    }
}
