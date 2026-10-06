package io.github.capitan0n.droynis.platform

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.capitan0n.droynis.checks.adb.adbChecks
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.checks.shizuku.shizukuChecks
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.core.Status
import kotlinx.coroutines.flow.toList
import io.github.capitan0n.droynis.platform.shizuku.ShizukuState
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Runs the real probes and checks on an emulator or device, from API 26 to the latest. */
@RunWith(AndroidJUnit4::class)
class AndroidPlatformTest {

    private val platform = AndroidPlatform(InstrumentationRegistry.getInstrumentation().targetContext)

    @After
    fun close() = platform.close()

    @Test
    fun probesReadRealValues() {
        assertValue(platform.keyguard.isDeviceSecure())
        assertValue(platform.build.securityPatch())
        assertValue(platform.settings.global("adb_enabled"))
        assertValue(platform.settings.system("screen_off_timeout"))
        assertValue(platform.policy.encryptionStatus())
        assertValue(platform.policy.activeAdmins())
        assertValue(platform.accessibility.enabledServices())
        assertValue(platform.network.activeNetwork())
        assertValue(platform.certificates.userCertificates())
        assertValue(platform.inputMethods.enabledKeyboards())
        assertValue(platform.permissionAudit.overview())

        assertValue(platform.radios.locationEnabled())

        val nfc = platform.radios.nfcEnabled()
        assertTrue("$nfc", nfc is Reading.Value || nfc is Reading.Unsupported) // emulators have no NFC

        val props = platform.properties.all()
        assertValue(props)
        assertTrue("getprop should list ro.build.version.sdk", "ro.build.version.sdk" in (props as Reading.Value).value)
        assertEquals(listOf("/system/bin/sh"), (platform.files.existing(listOf("/system/bin/sh", "/no/such/file")) as Reading.Value).value)
        assertValue(platform.webView.provider())
        // Emulators attest in software or not at all; either way the probe must not throw.
        platform.attestation.attest()

        val apps = platform.packages.installedApps()
        assertValue(apps)
        assertTrue("expected more than a handful of apps", (apps as Reading.Value).value.size > 5)

        val complexity = platform.keyguard.passwordComplexity()
        val advancedProtection = platform.policy.advancedProtection()
        if (Build.VERSION.SDK_INT >= 29) assertValue(complexity) else assertUnsupported(complexity)
        if (Build.VERSION.SDK_INT >= 36) assertValue(advancedProtection) else assertUnsupported(advancedProtection)
    }

    @Test
    fun missingSettingIsNullOrUnavailableRatherThanAnException() {
        val reading = platform.settings.global("droynis_no_such_setting")

        // Below API 31 an unknown key reads as unset; from API 31 a hidden key is access-denied.
        assertTrue("$reading", reading is Reading.Unavailable || (reading as? Reading.Value)?.value == null)
    }

    @Test
    fun deviceSummaryHasNoEmptyBasics() {
        val device = platform.build.device()

        assertFalse(device.model.isBlank())
        assertEquals(Build.VERSION.SDK_INT, device.sdkInt)
    }

    @Test
    fun noCheckCrashesOrTimesOutOnARealDevice(): Unit = runBlocking {
        val checks = baseChecks(platform) + adbChecks(platform) + shizukuChecks(platform)

        val findings = Scanner().scan(checks, platform.newScanContext()).toList()

        assertEquals(checks.size, findings.size)
        for (finding in findings) {
            val crashed = finding.status == Status.UNKNOWN &&
                (finding.summary.startsWith("Check failed") || finding.summary.startsWith("Timed out"))
            assertFalse("${finding.spec.id}: ${finding.summary}", crashed)
        }
    }

    @Test
    fun withoutAdbGrantsDumpsysIsRefusedRatherThanParsed() {
        // A test install has no adb grants unless someone gave them by hand.
        if (platform.detectGrants().isNotEmpty()) return

        val dump = platform.dumpsys.dump("appops")
        assertTrue("expected a refusal, got $dump", dump is Reading.Unavailable)
    }

    @Test
    fun withoutShizukuItsShellIsUnavailableRatherThanAnException() {
        // Test devices rarely run Shizuku; with it allowed, the scan above covers the shell instead.
        if (platform.shizuku.status().state == ShizukuState.CONNECTED) return

        assertFalse(Grant.SHIZUKU in platform.detectGrants())
        assertTrue(platform.shizuku.selinuxMode() is Reading.Unavailable)
        assertTrue(platform.shizuku.readSetting("global", "adb_enabled") is Reading.Unavailable)
    }

    private fun assertValue(reading: Reading<*>) {
        assertTrue("expected a value, got $reading", reading is Reading.Value)
    }

    private fun assertUnsupported(reading: Reading<*>) {
        assertTrue("expected unsupported, got $reading", reading is Reading.Unsupported)
    }
}
