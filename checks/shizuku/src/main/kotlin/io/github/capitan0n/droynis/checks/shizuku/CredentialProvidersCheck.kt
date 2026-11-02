package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.AppOrigin
import io.github.capitan0n.droynis.checks.base.AppRef
import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.checks.base.TRUSTED_NOTE
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.checks.base.onlyTrusted
import io.github.capitan0n.droynis.checks.base.originOf
import io.github.capitan0n.droynis.checks.base.settingEvidence
import io.github.capitan0n.droynis.checks.base.splitTrusted
import io.github.capitan0n.droynis.checks.base.trustOf
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
import io.github.capitan0n.droynis.core.evaluate

/**
 * Credential Manager providers (Android 14+), the services Settings › Passwords, passkeys & accounts
 * turns on. [CREDENTIAL_SERVICE] holds every enabled one, the set `CredentialManagerService` asks
 * on each sign-in, as flattened component names separated by ':'; [CREDENTIAL_SERVICE_PRIMARY]
 * the preferred ones, which only come first in the picker. Unset and empty both mean none to the
 * service. Both keys are hidden and not `@Readable` in Android 14 to 17, so only the shell user can
 * read them. Providers built into the system, such as Google Password Manager in Play services,
 * come with the phone: listed, not counted.
 */
class CredentialProvidersCheck(
    private val settings: SystemSettings,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "APPS-4201",
        category = Category.APPS,
        title = "Passkey and password providers",
        severity = Severity.NOTICE,
        explanation = "Since Android 14, password managers can serve passkeys and passwords to every app " +
            "through Android's Credential Manager. A provider you turn on keeps what you save with it, and is " +
            "asked each time an app or website wants you to sign in, so it also learns where you have " +
            "accounts. Providers that came with the phone are listed but don't count; any other one should " +
            "come from a developer you trust, and one installed from outside an app store is a warning. " +
            "Android hides this list from apps; the shell user Shizuku runs as can read it.",
        remediation = Remediation(
            text = "Open Settings › Passwords, passkeys & accounts and turn off the providers you don't use, " +
                "under Preferred service and Additional services.",
            settingsActions = listOf(SettingsActions.ACCOUNTS),
        ),
        minSdk = 34,
        requires = setOf(Grant.SHIZUKU),
        failsWhen = "a passkey or password provider from an app you installed is turned on " +
            "(a warning when it came from outside an app store)",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val enabled = settings.secure(CREDENTIAL_SERVICE)
        val primary = settings.secure(CREDENTIAL_SERVICE_PRIMARY)
        val raw = listOf(enabled.settingEvidence(CREDENTIAL_SERVICE), primary.settingEvidence(CREDENTIAL_SERVICE_PRIMARY))
        return enabled.evaluate("The passkey and password providers", raw) { enabledValue ->
            // A preferred provider belongs in the enabled list; one that isn't is listed all the same.
            val preferred = packagesOf((primary as? Reading.Value)?.value)
            val all = (packagesOf(enabledValue) + preferred).distinct()
            if (all.isEmpty()) {
                return@evaluate Outcome.pass("No passkey or password provider is turned on", raw)
            }
            val inventory = (packages.installedApps() as? Reading.Value)?.value?.associateBy { it.packageName }
            val providers = all.map { provider(it, inventory, preferred = it in preferred) }
            val countable = providers.filter { it.origin != AppOrigin.PREINSTALLED }
            val (trusted, counted) = context.splitTrusted(countable) { it.app.packageName }
            val evidence = providers.map { it.evidence(enabled.source, counted = it in countable, trusted = it in trusted) }
            val preinstalled = providers.size > countable.size

            if (counted.isEmpty() && trusted.isNotEmpty()) {
                val others = "apps that came with the phone".takeIf { preinstalled }
                return@evaluate Outcome.pass(onlyTrusted("provide passkeys and passwords", trusted.map { it.app.label }, others = others), evidence)
            }
            if (counted.isEmpty()) {
                return@evaluate Outcome.pass(
                    "Only providers that came with the phone are turned on: ${providers.map { it.app.label }.joinNames()}",
                    evidence,
                )
            }
            val sideloaded = counted.filter { it.origin == AppOrigin.SIDELOADED }.map { it.app.label }
            val n = counted.size
            Outcome.fail(
                "${count(n, "app")} ${if (n == 1) "provides" else "provide"} passkeys and passwords: " +
                    counted.map { it.app.label }.joinNames() +
                    if (sideloaded.isEmpty()) "" else "; ${sideloaded.joinNames()} ${if (sideloaded.size == 1) "comes" else "come"} from outside an app store",
                evidence,
                escalation = Severity.WARNING.takeIf { sideloaded.isNotEmpty() },
            )
        }
    }

    private fun provider(pkg: String, inventory: Map<String, InstalledApp>?, preferred: Boolean) =
        Provider(AppRef(pkg, packages.label(pkg)), originOf(pkg, inventory), preferred)

    /** One app's providers, and where the app came from. */
    private data class Provider(val app: AppRef, val origin: AppOrigin, val preferred: Boolean) {
        fun evidence(source: Source, counted: Boolean, trusted: Boolean) = Evidence(
            if (preferred) "Preferred provider" else "Provider",
            "${app.label} (${app.packageName})",
            source,
            note = origin.note + when {
                trusted -> "; $TRUSTED_NOTE"
                counted -> ""
                else -> "; not counted"
            },
            packageName = app.packageName,
            trust = trustOf(counted, trusted),
        )
    }

    companion object {
        /** `Settings.Secure.CREDENTIAL_SERVICE`: hidden, and not readable by apps (Android 14 to 17). */
        const val CREDENTIAL_SERVICE = "credential_service"

        /** `Settings.Secure.CREDENTIAL_SERVICE_PRIMARY`: hidden, and not readable by apps (Android 14 to 17). */
        const val CREDENTIAL_SERVICE_PRIMARY = "credential_service_primary"

        /** "pkg/cls:pkg2/.Cls" (flattened component names, as `CredentialManagerService` splits them) to packages. */
        internal fun packagesOf(raw: String?): List<String> =
            raw.orEmpty().split(':')
                .map { it.substringBefore('/').trim() }
                .filter { it.isNotEmpty() }
                .distinct()
    }
}
