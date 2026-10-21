package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Autofill service (APPS-4010), digital assistant (APPS-4011) and location all the time (APPS-4012). */
class AppAccessChecksTest {

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private val labels = mapOf(
        "com.x8bit.bitwarden" to "Bitwarden",
        "com.google.android.gms" to "Google Play services",
        "com.google.android.googlequicksearchbox" to "Google",
        "org.example.assistant" to "Helper",
        "org.osmand.plus" to "OsmAnd",
        "org.example.tracker" to "Tracker",
    )

    private val inventory = FakePackages(
        value(
            listOf(
                app("com.x8bit.bitwarden"),
                app("com.google.android.gms", system = true),
                app("com.google.android.googlequicksearchbox", system = true),
                app("org.example.assistant", installer = null),
                app("org.osmand.plus"),
                app("org.example.tracker", installer = "com.google.android.packageinstaller"),
            ),
        ),
        labels,
    )

    // Autofill service

    private fun autofill(state: Reading<AutofillState>) = AutofillServiceCheck(FakeAutofill(state), inventory)

    @Test
    fun `no autofill service, or a policy that turns it off, passes`() = runTest {
        assertEquals(Status.PASS, autofill(value(AutofillState(null))).status())
        assertEquals("No autofill service is selected", autofill(value(AutofillState(null))).outcome().summary)

        val disallowed = autofill(value(AutofillState("com.x8bit.bitwarden/.Autofill", allowed = false))).outcome()
        assertEquals(Status.PASS, disallowed.status)
        assertEquals("A device policy turns autofill off for this user", disallowed.summary)
    }

    @Test
    fun `autofill that came with the phone passes, listed with its origin`() = runTest {
        val outcome = autofill(value(AutofillState("com.google.android.gms/.autofill.service.AutofillService"))).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Google Play services, which came with the phone, fills in forms", outcome.summary)
        assertEquals("came with the phone", outcome.evidence.single().note)
    }

    @Test
    fun `an installed autofill service is a notice, a sideloaded one a warning`() = runTest {
        val store = autofill(value(AutofillState("com.x8bit.bitwarden/com.x8bit.bitwarden.Autofill"))).outcome()
        assertEquals(Status.FAIL, store.status)
        assertNull(store.escalation)
        assertEquals("Bitwarden fills in forms and passwords in every app", store.summary)
        assertEquals("Bitwarden (com.x8bit.bitwarden/com.x8bit.bitwarden.Autofill)", store.evidence.single().value)

        val sideloaded = autofill(value(AutofillState("org.example.tracker/.Fill"))).outcome()
        assertEquals(Severity.WARNING, sideloaded.escalation)
        assertTrue(sideloaded.summary.endsWith("; Tracker comes from outside an app store"), sideloaded.summary)
    }

    @Test
    fun `autofill that can't be read is never a pass`() = runTest {
        assertEquals(Status.UNSUPPORTED, autofill(unsupported("this phone has no autofill")).status())
        assertEquals(Status.UNKNOWN, autofill(unavailable("timed out")).status())
        assertEquals(28, autofill(unavailable()).spec.minSdk)
    }

    // Digital assistant

    private fun assistant(
        assist: Reading<String?>,
        voice: Reading<String?> = value(null),
        screenText: Reading<String?> = value(null),
        screenshot: Reading<String?> = value(null),
    ) = AssistantAppCheck(
        FakeSettings(
            secure = mapOf(
                "assistant" to assist,
                "voice_interaction_service" to voice,
                "assist_structure_enabled" to screenText,
                "assist_screenshot_enabled" to screenshot,
            ),
        ),
        inventory,
    )

    @Test
    fun `an empty assistant is none, an unset one is unknown`() = runTest {
        val none = assistant(value(""), voice = value("")).outcome()
        assertEquals(Status.PASS, none.status)
        assertEquals("No digital assistant app is set", none.summary)

        assertEquals(Status.UNKNOWN, assistant(value(null)).status())
        assertEquals(Status.UNKNOWN, assistant(unavailable("access denied")).status())
    }

    @Test
    fun `the assistant that came with the phone passes`() = runTest {
        val google = "com.google.android.googlequicksearchbox/com.google.android.voiceinteraction.GsaVoiceInteractionService"
        val outcome = assistant(value(google), voice = value(google)).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Google, which came with the phone, is the digital assistant", outcome.summary)
        // The screen switches are shown with Android's default when unset.
        assertEquals("(not set), on by default", outcome.evidence.single { it.label.startsWith("Use text from screen") }.value)
    }

    @Test
    fun `an installed assistant fails, and says when it can read the screen`() = runTest {
        val reads = assistant(value("org.osmand.plus/.Assist"), screenText = value("1")).outcome()
        assertEquals(Status.FAIL, reads.status)
        assertEquals("OsmAnd is the digital assistant and can read the screen when you call it", reads.summary)
        assertNull(reads.escalation)

        val blind = assistant(value("org.osmand.plus/.Assist"), screenText = value("0"), screenshot = value("0")).outcome()
        assertEquals("OsmAnd is the digital assistant", blind.summary)
        assertEquals(listOf("off", "off"), blind.evidence.filter { it.label.startsWith("Use ") }.map { it.value })
    }

    @Test
    fun `a sideloaded assistant is a warning, also when only its voice service is set`() = runTest {
        // Before Android 10 the assistant key can be unset while the voice interaction service decides.
        val outcome = assistant(value(null), voice = value("org.example.assistant/.Voice")).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertTrue(outcome.summary.startsWith("Helper is the digital assistant"), outcome.summary)
        assertEquals("installed from outside an app store", outcome.evidence.first().note)
    }

    // Location all the time

    private val background = BackgroundLocationCheck.BACKGROUND
    private val fine = "android.permission.ACCESS_FINE_LOCATION"
    private val coarse = "android.permission.ACCESS_COARSE_LOCATION"

    private fun location(holders: Reading<Map<String, Set<String>>>, packages: FakePackages = inventory) =
        BackgroundLocationCheck(FakePermissions(holders), packages)

    @Test
    fun `no app with location all the time passes`() = runTest {
        val outcome = location(value(mapOf("org.osmand.plus" to setOf(fine)))).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app may use location all the time", outcome.summary)
        assertEquals("none", outcome.evidence.single().value)
    }

    @Test
    fun `apps that came with the phone are counted, not named or failed`() = runTest {
        val packages = FakePackages(inventory.installedApps(), labels)
        val outcome = location(value(mapOf("com.google.android.gms" to setOf(background, fine))), packages).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps that came with the phone may use location all the time", outcome.summary)
        assertEquals("1", outcome.evidence.single().value)
        assertFalse("com.google.android.gms" in packages.labelled)
    }

    @Test
    fun `installed apps with location all the time fail, sideloaded ones as a warning`() = runTest {
        val outcome = location(
            value(
                mapOf(
                    "org.osmand.plus" to setOf(background, fine),
                    "org.example.tracker" to setOf(background, coarse),
                    "com.google.android.gms" to setOf(background, fine),
                ),
            ),
        ).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 apps may use location all the time: OsmAnd and Tracker; Tracker comes from outside an app store", outcome.summary)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals(3, outcome.evidence.size)
    }

    @Test
    fun `background location without a foreground grant gives no location`() = runTest {
        assertEquals(Status.PASS, location(value(mapOf("org.osmand.plus" to setOf(background)))).status())
    }

    @Test
    fun `unreadable permissions are unknown, and the check needs Android 10`() = runTest {
        assertEquals(Status.UNKNOWN, location(unavailable("package manager died")).status())
        assertEquals(29, location(unavailable()).spec.minSdk)
    }
}
