package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

/** Managed by an organization (INTG-1031). */
class ManagedDeviceCheckTest {

    private fun app(pkg: String, system: Boolean = false, installer: String? = "com.android.vending") =
        InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35)

    private val apps = listOf(
        app("com.example.mdm"),
        app("org.example.monitor", installer = null),
        app("com.google.android.apps.work.clouddpc", system = true),
        app("org.example.findphone"),
    )

    private fun admin(pkg: String, label: String, deviceOwner: Boolean = false, profileOwner: Boolean = false) =
        AdminApp(AppRef(pkg, label), isDeviceOwner = deviceOwner, isProfileOwner = profileOwner)

    private fun check(
        admins: Reading<List<AdminApp>>,
        organization: Reading<Boolean> = value(false),
    ) = ManagedDeviceCheck(FakePolicy(admins = admins), FakeProfiles(organizationOwned = organization), FakePackages(value(apps)))

    @Test
    fun `no owner and no organization passes, ordinary admins included`() = runTest {
        val outcome = check(value(listOf(admin("org.example.findphone", "Find Phone")))).outcome()

        assertEquals(Severity.INFO, check(value(emptyList())).spec.severity)
        assertEquals(Status.PASS, outcome.status)
        assertEquals("No device or profile owner manages this user", outcome.summary)
        assertEquals("no", outcome.evidence.single { it.label.startsWith("Owned by an organization") }.value)
    }

    @Test
    fun `a device owner from a store fails for information only`() = runTest {
        val outcome = check(value(listOf(admin("com.example.mdm", "Acme MDM", deviceOwner = true)))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("Acme MDM manages the whole phone as its device owner", outcome.summary)
        val row = outcome.evidence.single { it.label == "Device owner" }
        assertEquals("com.example.mdm", row.packageName)
        assertEquals(Trust.COUNTED, row.trust)
    }

    @Test
    fun `a sideloaded device owner is a warning`() = runTest {
        val outcome = check(value(listOf(admin("org.example.monitor", "Monitor", deviceOwner = true)))).outcome()

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals(
            "Monitor manages the whole phone as its device owner; Monitor comes from outside an app store",
            outcome.summary,
        )
    }

    @Test
    fun `a profile owner and an organization-owned phone fail`() = runTest {
        val profile = check(value(listOf(admin("com.google.android.apps.work.clouddpc", "Device Policy", profileOwner = true)))).outcome()
        assertEquals(Status.FAIL, profile.status)
        assertNull(profile.escalation)
        assertEquals("Device Policy manages this profile as its owner", profile.summary)

        val owned = check(value(emptyList()), organization = value(true)).outcome()
        assertEquals(Status.FAIL, owned.status)
        assertEquals("An organization owns this phone and manages its work profile", owned.summary)
    }

    @Test
    fun `a trusted owner is listed but not counted`() = runTest {
        val context = scanContext().copy(trustedApps = setOf("org.example.monitor"))
        val outcome = check(value(listOf(admin("org.example.monitor", "Monitor", deviceOwner = true)))).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust manage this phone: Monitor", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.single { it.label == "Device owner" }.trust)
    }

    @Test
    fun `half an answer is never a pass`() = runTest {
        // Admins read, organization ownership not: unknown.
        assertEquals(Status.UNKNOWN, check(value(emptyList()), organization = unavailable("denied")).outcome().status)
        // Before Android 11 the organization question doesn't exist: the admins alone decide.
        assertEquals(Status.PASS, check(value(emptyList()), organization = unsupported("needs Android 11")).outcome().status)
        // Admins unreadable: unknown, unless the organization answer already says managed.
        assertEquals(Status.UNKNOWN, check(unavailable("denied")).outcome().status)
        assertEquals(Status.FAIL, check(unavailable("denied"), organization = value(true)).outcome().status)
    }
}
