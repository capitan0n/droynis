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
 * User apps that use a known app store's package name but aren't signed with any of that store's
 * keys ([StoreKeys]). Android names an app's installer by package name only, so such an app makes
 * whatever it installs look like it came from that store.
 */
class StoreImpostorCheck(private val packages: PackageInventory) : Check {

    override val spec = CheckSpec(
        id = "SUSP-5009",
        category = Category.SUSPICIOUS_APPS,
        title = "Apps posing as an app store",
        severity = Severity.WARNING,
        explanation = "Android records which app installed each app by its package name only, and any app can " +
            "take an app store's package name on a phone where that store isn't installed. A fake F-Droid or " +
            "Google Play would make every app it installs look like it came from that store. Droynis compares " +
            "the signing key of each app store you installed with the keys the store publishes. A store that " +
            "came with the phone, or that another genuine app store installed, isn't compared.",
        remediation = Remediation(
            text = "Uninstall the app listed and the apps it installed, then get the store again from its own " +
                "website. Before installing, compare its signing key with the one the store publishes, for " +
                "example with AppVerifier. If you built the store yourself, trust it.",
            settingsActions = listOf(SettingsActions.APPS),
        ),
        timeout = 15.seconds,
        failsWhen = "a user app uses the package name of an app store whose signing keys Droynis knows, but none of " +
            "them (critical when it has installed other apps)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val apps = packages.installedApps()
        if (apps !is Reading.Value) {
            return Outcome.unknown("Could not read the installed apps", listOf(apps.toEvidence("Installed apps")))
        }
        val inventory = apps.value.associateBy { it.packageName }
        val stores = apps.value
            .filter { !it.isSystem }
            .mapNotNull { app -> StoreKeys.verify(app, inventory)?.let { app to it } }
        val evidence = mutableListOf(
            Evidence("App stores installed as user apps", stores.size.toString(), apps.source),
        )
        if (stores.isEmpty()) return Outcome.pass(NONE, evidence)

        val impostors = stores.filter { it.second == StoreKeys.Verdict.WRONG_KEY }.map { it.first }
        val (trusted, counted) = context.splitTrusted(impostors) { it.packageName }
        fun installedApps(store: InstalledApp) = apps.value.count { it.installer == store.packageName && it.packageName != store.packageName }

        evidence += stores.map { (app, verdict) ->
            val store = StoreKeys.STORES.getValue(app.packageName)
            val isImpostor = verdict == StoreKeys.Verdict.WRONG_KEY
            val installed = installedApps(app).takeIf { isImpostor && it > 0 }?.let { "; installed ${count(it, "app")}" }.orEmpty()
            Evidence(
                "App store",
                "${packages.label(app.packageName)} (${app.packageName})",
                apps.source,
                note = withTrustNote(note(verdict, store) + installed, app in trusted),
                packageName = app.packageName,
                trust = trustOf(counted = isImpostor, trusted = app in trusted),
            )
        }
        val unverified = stores.filter { it.second == StoreKeys.Verdict.UNVERIFIED || it.second == StoreKeys.Verdict.KEY_UNREAD }
        if (counted.isEmpty() && unverified.isNotEmpty()) {
            val verified = stores.count { it.second == StoreKeys.Verdict.KEY_MATCHES }
            val names = unverified.map { packages.label(it.first.packageName) }.sorted().joinNames()
            return Outcome.unknown("${count(verified, "store signature")} verified. Unverified: $names", evidence)
        }
        if (counted.isEmpty() && trusted.isNotEmpty()) {
            return Outcome.pass(onlyTrusted("use an app store's name without its key", trusted.map { packages.label(it.packageName) }), evidence)
        }
        if (counted.isEmpty()) {
            return Outcome.pass(NONE, evidence)
        }
        return Outcome.fail(
            "${count(counted.size, "app")} ${if (counted.size == 1) "uses" else "use"} an app store's name without its " +
                "signing key: ${counted.map { packages.label(it.packageName) }.joinNames()}",
            evidence,
            escalation = Severity.CRITICAL.takeIf { counted.any { installedApps(it) > 0 } },
        )
    }

    private fun note(verdict: StoreKeys.Verdict, store: StoreKeys.Store): String = when (verdict) {
        StoreKeys.Verdict.PREINSTALLED -> "came with the phone"
        StoreKeys.Verdict.KEY_MATCHES -> "signed with ${store.name}'s key"
        StoreKeys.Verdict.INSTALLED_BY_STORE -> "installed by another app store"
        StoreKeys.Verdict.UNVERIFIED -> if (store.keys.isEmpty()) {
            "not compared: ${store.name} publishes no signing key"
        } else {
            "signed with a key Droynis doesn't know for ${store.name}, which also ships builds others sign, such as F-Droid's"
        }
        StoreKeys.Verdict.KEY_UNREAD -> "its signing key could not be read"
        StoreKeys.Verdict.WRONG_KEY -> "not signed with any of ${store.name}'s keys"
    }

    internal companion object {
        const val NONE = "No app store impersonation detected"
    }
}
