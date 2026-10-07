package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Status
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DeviceStateChecksTest {

    private val lockedProps = FakeProperties(
        "ro.boot.flash.locked" to "1",
        "ro.boot.vbmeta.device_state" to "locked",
        "ro.boot.verifiedbootstate" to "green",
    )

    private suspend fun bootloader(attestation: FakeAttestation, props: FakeProperties = FakeProperties()) =
        BootloaderCheck(attestation, props).outcome()

    @Test
    fun `hardware attestation decides the bootloader state`() = runTest {
        assertEquals(Status.PASS, bootloader(FakeAttestation(attested(locked = true))).status)
        assertEquals(
            Status.PASS,
            bootloader(FakeAttestation(attested(locked = true, VerifiedBootState.SELF_SIGNED))).status,
        )
        assertEquals(Status.FAIL, bootloader(FakeAttestation(attested(locked = false))).status)
        assertEquals(
            Status.FAIL,
            bootloader(FakeAttestation(attested(locked = true, VerifiedBootState.UNVERIFIED))).status,
        )
        // Properties claiming "locked" cannot outvote the hardware.
        assertEquals(Status.FAIL, bootloader(FakeAttestation(attested(locked = false)), lockedProps).status)
    }

    @Test
    fun `without hardware attestation boot properties are the fallback`() = runTest {
        val software = FakeAttestation(attested(locked = true, level = SecurityLevel.SOFTWARE))
        val none = FakeAttestation(unavailable("ProviderException"))

        val locked = bootloader(none, lockedProps)
        assertEquals(Status.PASS, locked.status)
        assertTrue("not hardware-attested" in locked.summary)
        assertEquals(Status.PASS, bootloader(software, lockedProps).status)
        assertEquals(Status.FAIL, bootloader(none, FakeProperties("ro.boot.flash.locked" to "0")).status)
        assertEquals(Status.FAIL, bootloader(none, FakeProperties("ro.boot.verifiedbootstate" to "orange")).status)
        assertEquals(Status.UNKNOWN, bootloader(none, FakeProperties()).status)
        assertEquals(Status.UNKNOWN, bootloader(none, FakeProperties(unavailable("getprop failed"))).status)
    }

    @Test
    fun `bootloader evidence shows the attested state and the boot properties`() = runTest {
        val evidence = bootloader(FakeAttestation(attested(locked = true)), lockedProps).evidence
            .associate { it.label to it.value }

        assertEquals("trusted_environment", evidence["Attestation security level"])
        assertEquals("true", evidence["Device locked (attested)"])
        assertEquals("2026-09", evidence["OS patch level (attested)"])
        assertEquals("green", evidence["ro.boot.verifiedbootstate"])
    }

    @Test
    fun `oem unlocking`() = runTest {
        suspend fun status(vararg props: Pair<String, String>) = OemUnlockingCheck(FakeProperties(*props)).status()

        assertEquals(Status.FAIL, status("sys.oem_unlock_allowed" to "1"))
        assertEquals(Status.PASS, status("sys.oem_unlock_allowed" to "0"))
        assertEquals(Status.PASS, status("ro.oem_unlock_supported" to "0"))
        assertEquals(Status.UNKNOWN, status("ro.oem_unlock_supported" to "1"))
        assertEquals(Status.UNKNOWN, OemUnlockingCheck(FakeProperties(unavailable())).status())
    }

    @Test
    fun `root access`() = runTest {
        fun app(name: String) = InstalledApp(name, isSystem = false, isDebuggable = false, installer = null, targetSdk = 35)
        val clean = FakePackages(value(listOf(app("org.fdroid.fdroid"))))

        assertEquals(Status.PASS, RootAccessCheck(FakeFiles(), clean).status())

        val su = RootAccessCheck(FakeFiles(value(listOf("/system/bin/su"))), clean).outcome()
        assertEquals(Status.FAIL, su.status)
        assertEquals("Signs of root: su at /system/bin/su", su.summary)

        val magisk = RootAccessCheck(
            FakeFiles(),
            FakePackages(value(listOf(app("com.topjohnwu.magisk"))), mapOf("com.topjohnwu.magisk" to "Magisk")),
        ).outcome()
        assertEquals("Signs of root: Magisk installed", magisk.summary)

        assertEquals(Status.UNKNOWN, RootAccessCheck(FakeFiles(unavailable()), clean).status())
        assertEquals(Status.FAIL, RootAccessCheck(FakeFiles(value(listOf("/sbin/su"))), FakePackages(unavailable())).status())
    }

    @Test
    fun `android build`() = runTest {
        suspend fun outcome(type: String, tags: String, vararg props: Pair<String, String>) =
            AndroidBuildCheck(FakeBuildInfo(unavailable(), type, tags), FakeProperties(*props)).outcome()

        assertEquals(Status.PASS, outcome("user", "release-keys").status)
        assertEquals(Status.FAIL, outcome("userdebug", "release-keys").status)
        assertEquals("Insecure Android build: public test keys", outcome("user", "test-keys").summary)
        assertEquals(Status.FAIL, outcome("user", "release-keys", "ro.debuggable" to "1").status)
        assertEquals(Status.UNKNOWN, outcome("", "").status)
    }

    @Test
    fun `webview updates`() = runTest {
        suspend fun status(updated: LocalDate?) =
            WebViewCheck(FakeWebView(value(updated?.let { WebViewInfo("com.google.android.webview", "141.0", it) })))
                .status()

        assertEquals(Status.PASS, status(LocalDate.of(2026, 9, 20)))
        assertEquals(Status.PASS, status(LocalDate.of(2026, 8, 2))) // 60 days before the scan
        assertEquals(Status.FAIL, status(LocalDate.of(2026, 6, 1)))
        assertEquals(Status.UNKNOWN, status(LocalDate.of(2026, 12, 1)))
        assertEquals(Status.UNSUPPORTED, status(null))
        assertEquals(Status.UNKNOWN, WebViewCheck(FakeWebView(unavailable())).status())
    }

    @Test
    fun `a webview that came with the system is dated by its system image`() = runTest {
        fun check(built: LocalDate) =
            WebViewCheck(FakeWebView(value(WebViewInfo("com.android.webview", "141.0", built, fromSystemImage = true))))

        val current = check(LocalDate.of(2026, 9, 1)).outcome()
        assertEquals(Status.PASS, current.status)
        assertEquals("WebView 141.0 came with a system update 30 days ago", current.summary)
        assertEquals("com.android.webview 141.0, came with the system image of 2026-09-01", current.evidence.single().value)

        val stale = check(LocalDate.of(2026, 5, 4)).outcome()
        assertEquals(Status.FAIL, stale.status)
        assertEquals("WebView 141.0 came with a system update 150 days ago and was not updated since", stale.summary)
    }
}
