package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Capabilities
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
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

    private suspend fun bootloader(
        attestation: FakeAttestation,
        props: FakeProperties = FakeProperties(),
        files: FakeFiles = FakeFiles(),
        packages: FakePackages = FakePackages(),
        context: ScanContext = scanContext(),
    ) = BootloaderCheck(attestation, props, files, packages).run(context)

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
    fun `boot properties saying locked prove nothing on a rooted phone`() = runTest {
        val none = FakeAttestation(unavailable("no attestation extension"))
        val su = FakeFiles(value(listOf("/system/bin/su")))

        val rooted = bootloader(none, lockedProps, files = su)
        assertEquals(Status.UNKNOWN, rooted.status)
        assertEquals(
            "Boot properties say the bootloader is locked, but this phone is rooted, so they may be faked",
            rooted.summary,
        )
        assertEquals("/system/bin/su", rooted.evidence.single { it.label == "su binaries" }.value)

        val magisk = InstalledApp("com.topjohnwu.magisk", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35)
        val manager = bootloader(none, lockedProps, packages = FakePackages(value(listOf(magisk)), mapOf(magisk.packageName to "Magisk")))
        assertEquals(Status.UNKNOWN, manager.status)
        assertEquals("Magisk (com.topjohnwu.magisk)", manager.evidence.single { it.label == "Root or hooking app" }.value)

        val shell = bootloader(none, lockedProps, context = scanContext().copy(capabilities = Capabilities(setOf(Grant.ROOT))))
        assertEquals(Status.UNKNOWN, shell.status)
        assertEquals("granted to Droynis", shell.evidence.single { it.label == "Root access" }.value)

        // "Unlocked" is still reported honestly.
        assertEquals(Status.FAIL, bootloader(none, FakeProperties("ro.boot.flash.locked" to "0"), files = su).status)
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

        // adb without the authorization prompt is critical; a hidden or "1" value changes nothing.
        val openAdb = outcome("user", "release-keys", "ro.adb.secure" to "0")
        assertEquals(Status.FAIL, openAdb.status)
        assertEquals(Severity.CRITICAL, openAdb.escalation)
        assertEquals("Insecure Android build: adb without authorization (ro.adb.secure=0)", openAdb.summary)
        assertEquals("0", openAdb.evidence.single { it.label == "ro.adb.secure" }.value)
        val secured = outcome("user", "release-keys", "ro.adb.secure" to "1")
        assertEquals(Status.PASS, secured.status)
        assertEquals(null, outcome("userdebug", "release-keys", "ro.adb.secure" to "1").escalation)
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

    @Test
    fun `a placeholder webview date is unknown, not decades old`() = runTest {
        // Issue #6: a phone reported Google WebView as updated on 1970-01-10.
        fun check(updated: LocalDate, system: Boolean = false) = WebViewCheck(
            FakeWebView(value(WebViewInfo("com.google.android.webview", "145.0", updated, fromSystemImage = system))),
        )

        val epoch = check(LocalDate.of(1970, 1, 10)).outcome()
        assertEquals(Status.UNKNOWN, epoch.status)
        assertEquals("WebView reports a placeholder update date (1970-01-10)", epoch.summary)
        assertEquals("com.google.android.webview 145.0, no valid update date (reports 1970-01-10)", epoch.evidence.single().value)

        // A system WebView is dated by Build.TIME, which can be a placeholder too.
        assertEquals(Status.UNKNOWN, check(LocalDate.of(1970, 1, 1), system = true).status())
        assertEquals(Status.FAIL, check(LocalDate.of(2017, 1, 1)).status())
    }

    @Test
    fun `without a valid date an old webview is judged by its chromium version`() = runTest {
        // Issue #6 again: the same phone still reports 1970-01-10, but WebView 145 is from February 2026.
        fun check(version: String) = WebViewCheck(
            FakeWebView(value(WebViewInfo("com.google.android.webview", version, LocalDate.of(1970, 1, 10)))),
        )

        val old = check("145.0.7632.218").outcome()
        assertEquals(Status.FAIL, old.status)
        assertEquals("WebView 145.0.7632.218 is at least 233 days old, judging by its version", old.summary)
        assertEquals("2026-02-10 or earlier", old.evidence.single { it.label == "Chromium 145 released" }.value)

        // 152 came out 37 days before the scan, and later majors can't be dated: too new to tell.
        assertEquals(Status.UNKNOWN, check("152.0.7977.64").status())
        assertEquals(Status.UNKNOWN, check("156.0.8000.1").status())
        // Not Chromium's numbering: a vendor's own version, or too few parts to be sure.
        assertEquals(Status.UNKNOWN, check("14.0.0.302").status())
        assertEquals(Status.UNKNOWN, check("145.0").status())
        // Vanadium adds a fifth part; Chromium before 94 is bounded by 94's date.
        assertEquals(Status.FAIL, check("145.0.7632.218.0").status())
        assertEquals(Status.FAIL, check("90.0.4430.91").status())
    }

    @Test
    fun `chromium release bound`() {
        assertEquals(145, WebViewCheck.chromiumMajor("145.0.7632.218"))
        assertEquals(null, WebViewCheck.chromiumMajor("57.0.2987.132"))
        assertEquals(LocalDate.of(2026, 8, 25), WebViewCheck.releasedBy(152))
        assertEquals(LocalDate.of(2026, 2, 10), WebViewCheck.releasedBy(145))
        // A bound, never too early: Chromium 120 reached stable on 2023-12-05.
        assertEquals(LocalDate.of(2024, 3, 12), WebViewCheck.releasedBy(120))
        assertEquals(WebViewCheck.releasedBy(94), WebViewCheck.releasedBy(80))
        assertEquals(null, WebViewCheck.releasedBy(153))
    }
}
