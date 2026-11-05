package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.core.Trust
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

/**
 * Device controls on the lock screen (ACCS-2202), passkey and password providers (APPS-4201) and
 * clipboard access alerts (APPS-4202): hidden Settings keys only the shell user can read.
 */
class ShizukuSettingsChecksTest {

    private val shellSource = Source("settings get secure", Grant.SHIZUKU)
    private val context = ScanContext(ZonedDateTime.of(2026, 11, 2, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun value(raw: String?): Reading<String?> = Reading.Value(raw, shellSource)

    private val denied: Reading<String?> = Reading.Unavailable("neither Shizuku nor root is connected", shellSource)

    /** Keys missing from [secure] read as unset. */
    private fun settings(vararg secure: Pair<String, Reading<String?>>) = object : SystemSettings {
        private val map = secure.toMap()
        override fun global(key: String) = value(null)
        override fun secure(key: String) = map[key] ?: value(null)
        override fun system(key: String) = value(null)
    }

    private suspend fun Check.outcome(trusting: Set<String> = emptySet()): Outcome = run(context.copy(trustedApps = trusting))

    // Device controls on the lock screen

    private fun controls(show: Reading<String?> = value(null), trivial: Reading<String?> = value(null), wallet: Reading<String?> = value(null)) =
        LockScreenControlsCheck(
            settings(
                LockScreenControlsCheck.LOCKSCREEN_SHOW_CONTROLS to show,
                LockScreenControlsCheck.LOCKSCREEN_ALLOW_TRIVIAL_CONTROLS to trivial,
                LockScreenControlsCheck.LOCKSCREEN_SHOW_WALLET to wallet,
            ),
        )

    @Test
    fun `lock screen controls need the Shizuku tier and Android 13`() {
        val spec = controls().spec
        assertEquals(Tier.SHIZUKU, spec.requiredTier)
        assertEquals(33, spec.minSdk)
    }

    @Test
    fun `controls that act while locked fail`() = runTest {
        val outcome = controls(show = value("1"), trivial = value("1")).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("Device controls on the lock screen work without unlocking the phone", outcome.summary)
        assertEquals(listOf("on", "on", "(not set), off by default"), outcome.evidence.map { it.value })
    }

    @Test
    fun `controls hidden while locked, or that ask for the unlock, pass`() = runTest {
        val hidden = controls(show = value("0"), trivial = value("1")).outcome()
        assertEquals(Status.PASS, hidden.status)
        assertEquals("Device controls open only after unlocking the phone", hidden.summary)

        // SystemUI reads both switches with a default of 0.
        assertEquals(Status.PASS, controls().outcome().status)

        val asks = controls(show = value("1"), trivial = value(null)).outcome()
        assertEquals(Status.PASS, asks.status)
        assertEquals("Device controls show on the lock screen, but each one asks for the unlock", asks.summary)
        assertEquals(Status.PASS, controls(show = value("1"), trivial = value("0")).outcome().status)
    }

    @Test
    fun `the wallet is evidence only`() = runTest {
        val outcome = controls(show = value("0"), wallet = value("1")).outcome()

        assertEquals(Status.PASS, outcome.status)
        val wallet = outcome.evidence.single { it.label.startsWith("Show wallet") }
        assertEquals("on", wallet.value)
        assertEquals("only shows your cards; not counted", wallet.note)
    }

    @Test
    fun `unreadable or odd lock screen switches are unknown`() = runTest {
        assertEquals(Status.UNKNOWN, controls(show = denied).outcome().status)
        assertEquals(Status.UNKNOWN, controls(show = value("1"), trivial = denied).outcome().status)
        assertEquals(Status.UNKNOWN, controls(show = value("yes")).outcome().status)
        assertEquals(Status.UNKNOWN, controls(show = value("1"), trivial = value("2")).outcome().status)
        // An unreadable "Control from locked device" doesn't matter while the controls stay hidden.
        assertEquals(Status.PASS, controls(show = value("0"), trivial = denied).outcome().status)
    }

    // Passkey and password providers

    private val bitwarden = "com.x8bit.bitwarden"
    private val keepass = "com.kunzisoft.keepass.libre"
    private val gms = "com.google.android.gms"
    private val stranger = "org.example.vault"

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private val inventory = object : PackageInventory {
        private val labels = mapOf(bitwarden to "Bitwarden", keepass to "KeePassDX", gms to "Google Play services", stranger to "Vault")
        override fun installedApps(): Reading<List<InstalledApp>> = Reading.Value(
            listOf(app(bitwarden, installer = "com.android.vending"), app(keepass), app(gms, system = true), app(stranger, installer = null)),
            shellSource,
        )
        override fun label(packageName: String) = labels[packageName] ?: packageName
    }

    private fun providers(enabled: Reading<String?>, primary: Reading<String?> = value(null)) = CredentialProvidersCheck(
        settings(
            CredentialProvidersCheck.CREDENTIAL_SERVICE to enabled,
            CredentialProvidersCheck.CREDENTIAL_SERVICE_PRIMARY to primary,
        ),
        inventory,
    )

    @Test
    fun `providers need the Shizuku tier and Android 14`() {
        val spec = providers(value(null)).spec
        assertEquals(Tier.SHIZUKU, spec.requiredTier)
        assertEquals(34, spec.minSdk)
    }

    @Test
    fun `no provider, or only the phone's own, passes`() = runTest {
        for (none in listOf(value(null), value(""), value(" : "))) {
            val outcome = providers(none).outcome()
            assertEquals(Status.PASS, outcome.status)
            assertEquals("No passkey or password provider is turned on", outcome.summary)
        }

        val own = providers(value("$gms/com.google.android.gms.auth.api.credentials.credman.service.PasswordAndPasskeyService")).outcome()
        assertEquals(Status.PASS, own.status)
        assertEquals("Only providers that came with the phone are turned on: Google Play services", own.summary)
        assertEquals(Trust.NOT_COUNTED, own.evidence.single().trust)
        assertEquals("came with the phone; not counted", own.evidence.single().note)
    }

    @Test
    fun `an installed provider fails, the preferred one named as such`() = runTest {
        val outcome = providers(
            enabled = value("$bitwarden/com.x8bit.bitwarden.Autofill:$gms/.Credman:$keepass/.credentialprovider.Service"),
            primary = value("$bitwarden/com.x8bit.bitwarden.Autofill"),
        ).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("2 apps provide passkeys and passwords: Bitwarden and KeePassDX", outcome.summary)
        assertEquals(listOf("Preferred provider", "Provider", "Provider"), outcome.evidence.map { it.label })
        assertEquals(listOf(Trust.COUNTED, Trust.NOT_COUNTED, Trust.COUNTED), outcome.evidence.map { it.trust })
        assertEquals(listOf(bitwarden, gms, keepass), outcome.evidence.map { it.packageName })
    }

    @Test
    fun `a sideloaded provider is a warning, one only in the preferred list still counts`() = runTest {
        val outcome = providers(enabled = value(""), primary = value("$stranger/.Provider")).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals("1 app provides passkeys and passwords: Vault; Vault comes from outside an app store", outcome.summary)
        assertEquals("installed from outside an app store", outcome.evidence.single().note)
    }

    @Test
    fun `a trusted provider is listed but not counted`() = runTest {
        val outcome = providers(value("$bitwarden/.A:$gms/.B")).outcome(trusting = setOf(bitwarden))

        assertEquals(Status.PASS, outcome.status)
        assertEquals(
            "Only apps that came with the phone and apps you trust provide passkeys and passwords: Bitwarden",
            outcome.summary,
        )
        assertEquals(listOf(Trust.TRUSTED, Trust.NOT_COUNTED), outcome.evidence.map { it.trust })
        assertTrue(outcome.evidence.first().note!!.endsWith("trusted by you, not counted"))
    }

    @Test
    fun `an unreadable provider list is never a pass`() = runTest {
        assertEquals(Status.UNKNOWN, providers(denied).outcome().status)
        // The preferred list only names the first choice: the enabled list still decides.
        assertEquals(Status.FAIL, providers(value("$keepass/.S"), primary = denied).outcome().status)
    }

    @Test
    fun `component lists split like Credential Manager splits them`() {
        assertEquals(listOf(bitwarden, keepass), CredentialProvidersCheck.packagesOf("$bitwarden/.A:$keepass/.B:$bitwarden/.C"))
        assertEquals(emptyList(), CredentialProvidersCheck.packagesOf(null))
    }

    // Clipboard access alerts

    private fun clipboard(raw: Reading<String?>) =
        ClipboardAlertsCheck(settings(ClipboardAlertsCheck.CLIPBOARD_SHOW_ACCESS_NOTIFICATIONS to raw))

    @Test
    fun `clipboard alerts need the Shizuku tier and Android 12`() {
        val spec = clipboard(value(null)).spec
        assertEquals(Tier.SHIZUKU, spec.requiredTier)
        assertEquals(31, spec.minSdk)
    }

    @Test
    fun `clipboard alerts on, or never changed, pass`() = runTest {
        val on = clipboard(value("1")).outcome()
        assertEquals(Status.PASS, on.status)
        assertEquals("Android tells you when an app reads the clipboard", on.summary)

        val unset = clipboard(value(null)).outcome()
        assertEquals(Status.PASS, unset.status)
        assertEquals("(not set), on by default", unset.evidence.single().value)
    }

    @Test
    fun `clipboard alerts turned off fail, unreadable or odd ones are unknown`() = runTest {
        val off = clipboard(value("0")).outcome()
        assertEquals(Status.FAIL, off.status)
        assertEquals("Android no longer tells you when an app reads the clipboard", off.summary)

        assertEquals(Status.UNKNOWN, clipboard(denied).outcome().status)
        assertEquals(Status.UNKNOWN, clipboard(value("true")).outcome().status)
    }
}
