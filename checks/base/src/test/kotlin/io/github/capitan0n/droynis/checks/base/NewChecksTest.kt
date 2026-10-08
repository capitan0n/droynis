package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class NewChecksTest {

    @Test
    fun `a pattern or simple PIN fails, medium and strong locks pass`() = runTest {
        suspend fun status(level: PasswordComplexity, secure: Boolean = true) =
            LockStrengthCheck(FakeKeyguard(value(secure), value(level))).run(scanContext(sdk = 36))

        assertEquals(Status.FAIL, status(PasswordComplexity.LOW).status)
        assertEquals("The screen lock is a pattern or a simple PIN", status(PasswordComplexity.LOW).summary)
        assertEquals(Status.PASS, status(PasswordComplexity.MEDIUM).status)
        assertEquals(Status.PASS, status(PasswordComplexity.HIGH).status)
        // No lock at all is ACCS-2001's critical failure, not this check's.
        assertEquals(Status.UNSUPPORTED, status(PasswordComplexity.NONE, secure = false).status)
        assertEquals(Status.UNKNOWN, status(PasswordComplexity.NONE).status)
        assertEquals(
            Status.UNKNOWN,
            LockStrengthCheck(FakeKeyguard(value(true), unavailable())).run(scanContext()).status,
        )
    }

    @Test
    fun `only the default SMS and phone apps may read SMS and the call log`() = runTest {
        val apps = FakePackages(
            value(
                listOf(
                    app("com.google.android.apps.messaging", system = true),
                    app("com.samsung.android.dialer", system = true),
                    app("org.kde.kdeconnect_tp"),
                    app("com.example.flashlight", installer = null),
                    app("com.android.carrierservices", system = true),
                ),
            ),
            labels = mapOf("org.kde.kdeconnect_tp" to "KDE Connect", "com.example.flashlight" to "Flashlight"),
        )
        val defaults = FakeDefaultApps(value("com.google.android.apps.messaging"), value("com.samsung.android.dialer"))
        fun check(vararg held: Pair<String, Set<String>>) =
            SmsAccessCheck(FakePermissions(value(held.toMap())), defaults, apps)

        val expected = check(
            "com.google.android.apps.messaging" to SmsAccessCheck.SMS,
            "com.samsung.android.dialer" to SmsAccessCheck.CALL_LOG,
            "com.android.carrierservices" to SmsAccessCheck.SMS,
        ).outcome()
        assertEquals(Status.PASS, expected.status)

        val storeApp = check("org.kde.kdeconnect_tp" to SmsAccessCheck.SMS).outcome()
        assertEquals(Status.FAIL, storeApp.status)
        assertNull(storeApp.escalation)
        assertEquals("1 app can read your SMS or call log: KDE Connect", storeApp.summary)

        val sideloaded = check("com.example.flashlight" to SmsAccessCheck.SMS + SmsAccessCheck.CALL_LOG).outcome()
        assertEquals(Severity.WARNING, sideloaded.escalation)
        assertEquals("Can read your SMS and call log", sideloaded.evidence[2].label)

        // The default SMS app reading the call log is not its role.
        val smsReadingCalls = check("com.google.android.apps.messaging" to SmsAccessCheck.CALL_LOG).outcome()
        assertEquals(Status.PASS, smsReadingCalls.status) // preinstalled: listed, not counted
        assertEquals("1", smsReadingCalls.evidence.last().value)

        // Preinstalled holders are only counted, so their labels are never loaded.
        apps.labelled.clear()
        check("com.android.carrierservices" to SmsAccessCheck.SMS, "org.kde.kdeconnect_tp" to SmsAccessCheck.SMS).outcome()
        assertTrue("com.android.carrierservices" !in apps.labelled)
        assertTrue("org.kde.kdeconnect_tp" in apps.labelled)

        assertEquals(
            Status.UNKNOWN,
            SmsAccessCheck(FakePermissions(unavailable()), defaults, apps).status(),
        )
    }

    private fun app(pkg: String, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)
}
