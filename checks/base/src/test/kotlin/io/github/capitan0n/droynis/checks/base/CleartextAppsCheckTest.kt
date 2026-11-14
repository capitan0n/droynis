package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

/** Apps that allow unencrypted connections (APPS-4018). */
class CleartextAppsCheckTest {

    private fun app(pkg: String, cleartext: Boolean, system: Boolean = false, installer: String? = "org.fdroid.fdroid") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35, usesCleartextTraffic = cleartext)

    private val apps = listOf(
        app("com.android.systemui", cleartext = true, system = true),
        app("org.example.radio", cleartext = true),
        app("org.example.camera", cleartext = true, installer = null),
        app("org.example.offline", cleartext = true),
        app("org.thoughtcrime.securesms", cleartext = false),
    )

    private val labels = mapOf(
        "org.example.radio" to "Radio",
        "org.example.camera" to "IP Camera",
        "org.example.offline" to "Offline Notes",
        "org.thoughtcrime.securesms" to "Signal",
    )

    private val internet = setOf(CleartextAppsCheck.INTERNET)
    private val online = mapOf(
        "com.android.systemui" to internet,
        "org.example.radio" to internet,
        "org.example.camera" to internet,
        "org.thoughtcrime.securesms" to internet,
    )

    private fun check(
        installed: Reading<List<InstalledApp>> = value(apps),
        holders: Reading<Map<String, Set<String>>> = value(online),
    ) = CleartextAppsCheck(FakePackages(installed, labels), FakePermissions(holders))

    @Test
    fun `user apps with network access that declare cleartext are listed for information`() = runTest {
        val outcome = check().outcome()

        assertEquals(Severity.INFO, check().spec.severity)
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals(
            "2 apps may connect without encryption: IP Camera and Radio; IP Camera comes from outside an app store",
            outcome.summary,
        )
        val rows = outcome.evidence.filter { it.label == "Allows unencrypted connections" }
        // System apps, apps without INTERNET and apps that don't declare it are left out.
        assertEquals(listOf("org.example.camera", "org.example.radio"), rows.map { it.packageName })
        assertEquals("4", outcome.evidence.single { it.label == "User apps inspected" }.value)
    }

    @Test
    fun `no declaring app passes without asking for permissions`() = runTest {
        val outcome = check(value(apps.filter { !it.usesCleartextTraffic || it.isSystem }), unavailable("unused")).outcome()

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app you installed with network access allows unencrypted connections", outcome.summary)
    }

    @Test
    fun `a declaring app without network access passes`() = runTest {
        val outcome = check(value(listOf(app("org.example.offline", cleartext = true)))).outcome()

        assertEquals(Status.PASS, outcome.status)
    }

    @Test
    fun `trusted apps are listed but not counted`() = runTest {
        val context = scanContext().copy(trustedApps = setOf("org.example.radio", "org.example.camera"))
        val outcome = check().run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust allow unencrypted connections: IP Camera and Radio", outcome.summary)
        assertEquals(
            listOf(Trust.TRUSTED, Trust.TRUSTED),
            outcome.evidence.filter { it.label == "Allows unencrypted connections" }.map { it.trust },
        )
    }

    @Test
    fun `an unreadable app list or permission list is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, check(installed = unavailable("denied")).outcome().status)
        val outcome = check(holders = unavailable("denied")).outcome()
        assertEquals(Status.UNKNOWN, outcome.status)
        assertEquals(
            "3 apps allow unencrypted connections, but which of them have network access could not be read",
            outcome.summary,
        )
    }
}
