package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class IntegrityChecksTest {

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(
        "ACTIVE_PER_USER, PASS",
        "ACTIVE, PASS",
        "ACTIVE_DEFAULT_KEY, FAIL",
        "ACTIVATING, UNKNOWN",
        "INACTIVE, FAIL",
        "UNSUPPORTED, FAIL",
    )
    fun `storage encryption`(encryption: EncryptionStatus, status: Status) = runTest {
        assertEquals(status, StorageEncryptionCheck(FakePolicy(encryption = value(encryption))).status())
    }

    @Test
    fun `missing encryption is critical`() = runTest {
        assertEquals(Severity.CRITICAL, StorageEncryptionCheck(FakePolicy()).spec.severity)
        assertEquals(Status.UNKNOWN, StorageEncryptionCheck(FakePolicy(encryption = unavailable())).status())
    }

    @Test
    fun `advanced protection`() = runTest {
        assertEquals(Status.PASS, advancedProtection(value(true)).status())
        assertEquals(Status.FAIL, advancedProtection(value(false)).status())
        assertEquals(Status.UNSUPPORTED, advancedProtection(unsupported("needs API 36")).status())
        assertEquals(36, advancedProtection().spec.minSdk)
        assertEquals(Severity.INFO, advancedProtection().spec.severity)
    }

    @Test
    fun `GrapheneOS has no Advanced Protection switch, so the check is not available there`() = runTest {
        val outcome = advancedProtection(value(false), webView = webView(GrapheneOs.VANADIUM_WEBVIEW)).outcome()
        assertEquals(Status.UNSUPPORTED, outcome.status)
        assertEquals(AdvancedProtectionCheck.GRAPHENEOS_SUMMARY, outcome.summary)
        assertEquals(listOf("Advanced Protection enabled", "WebView provider"), outcome.evidence.map { it.label })
        assertEquals(GrapheneOs.VANADIUM_WEBVIEW, outcome.evidence.last().value)

        // Its preinstalled apps tell as well, should the WebView not.
        val apps = FakePackages(
            value(listOf(app("app.grapheneos.info", system = true), app("app.grapheneos.apps", system = true))),
        )
        val byApps = advancedProtection(value(false), FakeWebView(unavailable()), apps).outcome()
        assertEquals(Status.UNSUPPORTED, byApps.status)
        assertEquals("app.grapheneos.apps and app.grapheneos.info", byApps.evidence.last().value)
        assertEquals(Status.UNSUPPORTED, advancedProtection(value(false), packages = apps).status())

        // Should GrapheneOS ever offer it, the switch decides as everywhere else.
        val vanadium = webView(GrapheneOs.VANADIUM_WEBVIEW)
        assertEquals(Status.PASS, advancedProtection(value(true), vanadium).status())
    }

    @Test
    fun `GrapheneOS apps installed on another Android don't hide the check`() = runTest {
        // GrapheneOS Camera is published for every Android; installed from a store it isn't a system app.
        val apps = FakePackages(
            value(
                listOf(
                    app("app.grapheneos.camera", system = false),
                    app("com.android.settings", system = true),
                    app("com.google.android.gms", system = true),
                ),
            ),
        )
        val outcome = advancedProtection(value(false), webView("com.google.android.webview"), apps).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals(1, outcome.evidence.size)
    }

    @Test
    fun `an unreadable WebView and app list leave the check failing`() = runTest {
        assertEquals(
            Status.FAIL,
            advancedProtection(value(false), FakeWebView(unavailable()), FakePackages(unavailable())).status(),
        )
    }

    private fun advancedProtection(
        enabled: Reading<Boolean> = value(false),
        webView: WebViewProbe = webView("com.google.android.webview"),
        packages: PackageInventory = FakePackages(),
    ) = AdvancedProtectionCheck(FakePolicy(advancedProtection = enabled), webView, packages)

    private fun webView(pkg: String) = FakeWebView(value(WebViewInfo(pkg, "141.0", LocalDate.of(2026, 9, 20))))

    private fun app(pkg: String, system: Boolean) =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = null, targetSdk = 36)
}
