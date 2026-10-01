package io.github.capitan0n.droynis.platform

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.capitan0n.droynis.checks.base.baseChecks
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Scanner
import io.github.capitan0n.droynis.core.Status
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Runs the real probes and checks on an emulator or device, from API 26 to the latest. */
@RunWith(AndroidJUnit4::class)
class AndroidPlatformTest {

    private val platform = AndroidPlatform(InstrumentationRegistry.getInstrumentation().targetContext)

    @Test
    fun probesReadRealValues() {
        assertValue(platform.keyguard.isDeviceSecure())
        assertValue(platform.build.securityPatch())
        assertValue(platform.settings.global("adb_enabled"))

        val complexity = platform.keyguard.passwordComplexity()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            assertValue(complexity)
        } else {
            assertTrue("$complexity", complexity is Reading.Unsupported)
        }
    }

    @Test
    fun missingSettingIsUnavailableRatherThanAnException() {
        val reading = platform.settings.global("droynis_no_such_setting")

        assertTrue("$reading", reading is Reading.Unavailable)
    }

    @Test
    fun baseChecksReachAVerdict(): Unit = runBlocking {
        val checks = baseChecks(platform)

        val findings = Scanner().scan(checks, platform.newScanContext()).toList()

        assertEquals(checks.size, findings.size)
        for (finding in findings) {
            assertTrue(
                "${finding.spec.id}: ${finding.status} ${finding.summary}",
                finding.status == Status.PASS || finding.status == Status.FAIL,
            )
        }
    }

    private fun assertValue(reading: Reading<*>) {
        assertTrue("expected a value, got $reading", reading is Reading.Value)
    }
}
