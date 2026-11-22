package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class ScreenCaptureCheckTest {

    private val quickSupport = InstalledApp("com.example.remote", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35)
    private val castApp = InstalledApp("com.example.cast", isSystem = false, isDebuggable = false, installer = "com.android.vending", targetSdk = 35)
    private val systemUi = InstalledApp("com.android.systemui", isSystem = true, isDebuggable = false, installer = null, targetSdk = 35)
    private val packages = FakePackages(
        value(listOf(quickSupport, castApp, systemUi)),
        mapOf(quickSupport.packageName to "Remote Help", castApp.packageName to "Cast It"),
    )

    private fun check(
        recording: io.github.capitan0n.droynis.core.Reading<ScreenRecording>,
        vararg displays: ExtraDisplay,
    ) = ScreenCaptureCheck(FakeScreenCapture(recording, value(displays.toList())), packages)

    private val remote = ExtraDisplay(2, "RemoteDisplay", quickSupport.packageName)
    private val cast = ExtraDisplay(3, "Cast", castApp.packageName)

    @Test
    fun `Android 15 says the screen is recorded`() = runTest {
        val unnamed = check(value(ScreenRecording.RECORDED)).outcome()
        assertEquals(Status.FAIL, unnamed.status)
        assertEquals("The screen is being recorded or shared right now", unnamed.summary)
        assertNull(unnamed.escalation)

        // The app that made a display is the likely one; from outside an app store it is critical.
        val named = check(value(ScreenRecording.RECORDED), remote).outcome()
        assertEquals("The screen is being recorded or shared right now, likely by Remote Help", named.summary)
        assertEquals(Severity.CRITICAL, named.escalation)
        assertEquals(Trust.COUNTED, named.evidence.last().trust)
    }

    @Test
    fun `Android 15 says it isn't`() = runTest {
        assertEquals(Status.PASS, check(value(ScreenRecording.NOT_RECORDED)).status())
        // A display of an app's own, such as a cast, while the screen isn't recorded: listed, not counted.
        val outcome = check(value(ScreenRecording.NOT_RECORDED), cast).outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals(Trust.NOT_COUNTED, outcome.evidence.last().trust)
    }

    @Test
    fun `before Android 15 only displays tell`() = runTest {
        assertEquals(Status.UNSUPPORTED, check(unsupported("needs Android 15")).status())

        val outcome = check(unsupported("needs Android 15"), cast).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("Cast It shows the screen on a display of its own, which can mirror or record it", outcome.summary)
        assertNull(outcome.escalation)

        // Displays the system made, and physical screens, don't count.
        val system = check(unsupported(), ExtraDisplay(4, "Screen recording", systemUi.packageName), ExtraDisplay(5, "HDMI", null))
        assertEquals(Status.UNSUPPORTED, system.status())
    }

    @Test
    fun `scheduled scans can't tell`() = runTest {
        // Droynis isn't on screen, so Android doesn't answer.
        assertEquals(Status.UNKNOWN, check(unavailable("Droynis isn't on screen")).status())
        assertEquals(
            Status.UNKNOWN,
            ScreenCaptureCheck(FakeScreenCapture(unsupported(), unavailable()), packages).status(),
        )
    }

    @Test
    fun `a trusted app's display`() = runTest {
        val outcome = check(unsupported(), cast).run(scanContext().copy(trustedApps = setOf(castApp.packageName)))
        assertEquals(Status.PASS, outcome.status)
        assertEquals(Trust.TRUSTED, outcome.evidence.last().trust)
    }
}
