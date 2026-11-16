package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class StoreKeysTest {

    private val fdroidKey = "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab"
    private val otherKey = "0000000000000000000000000000000000000000000000000000000000000000"

    private fun app(
        pkg: String,
        installer: String? = null,
        system: Boolean = false,
        signers: Set<String>? = null,
    ) = InstalledApp(pkg, isSystem = system, isDebuggable = false, installer = installer, targetSdk = 35, signerSha256 = signers)

    private fun inventory(vararg apps: InstalledApp) = apps.associateBy { it.packageName }

    @Test
    fun `every known store has keys or says it has none`() {
        val stores = UnknownSourceAppsCheck.KNOWN_STORES + UnknownSourceAppsCheck.PLUGIN_INSTALLERS
        assertEquals(stores, stores.filter { it in StoreKeys.STORES }.toSet(), "add the missing stores to StoreKeys")
        StoreKeys.STORES.values.flatMap { it.keys }.forEach { assertTrue(Regex("[0-9a-f]{64}").matches(it), it) }
        // A store whose keys Droynis knows all of has at least one.
        StoreKeys.STORES.values.filter { it.allKeysKnown }.forEach { assertTrue(it.keys.isNotEmpty(), it.packageName) }
    }

    @Test
    fun `fingerprints are compared without colons or case`() {
        assertEquals(fdroidKey, StoreKeys.normalize("43:23:8D:51:2C:1E:5E:B2:D6:56:9F:4A:3A:FB:F5:52:34:18:B8:2E:0A:3E:D1:55:27:70:AB:B9:A9:C9:CC:AB"))
        assertTrue(StoreKeys.normalize("ED:88:59:C5:5A:F3:11:16:26:58:B9:4A:F9:82:B9:F0:91:DC:D2:76:28:D4:DE:34:86:D1:21:7E:BF:3C:99:35") in
            StoreKeys.STORES.getValue("com.looker.droidify").keys)
    }

    @Test
    fun `verdicts`() {
        val genuine = app("org.fdroid.fdroid", signers = setOf(fdroidKey))
        val fake = app("org.fdroid.fdroid", signers = setOf(otherKey))
        assertEquals(StoreKeys.Verdict.KEY_MATCHES, StoreKeys.verify(genuine, inventory(genuine)))
        assertEquals(StoreKeys.Verdict.WRONG_KEY, StoreKeys.verify(fake, inventory(fake)))
        assertEquals(StoreKeys.Verdict.PREINSTALLED, StoreKeys.verify(app("com.android.vending", system = true), emptyMap()))
        assertEquals(StoreKeys.Verdict.KEY_UNREAD, StoreKeys.verify(app("org.fdroid.fdroid", signers = emptySet()), emptyMap()))
        assertEquals(StoreKeys.Verdict.KEY_UNREAD, StoreKeys.verify(app("org.fdroid.fdroid"), emptyMap()))
        assertNull(StoreKeys.verify(app("org.example.notastore", signers = setOf(otherKey)), emptyMap()))

        // Aurora Store from F-Droid is signed with a key F-Droid keeps: unverified, not fake.
        val aurora = app("com.aurora.store", installer = "com.aurora.store", signers = setOf(otherKey))
        assertEquals(StoreKeys.Verdict.UNVERIFIED, StoreKeys.verify(aurora, inventory(aurora)))
        // Neo Store publishes no key; installed by a genuine F-Droid, it counts as checked.
        val neo = app("com.machiav3lli.fdroid", installer = genuine.packageName, signers = setOf(otherKey))
        assertEquals(StoreKeys.Verdict.INSTALLED_BY_STORE, StoreKeys.verify(neo, inventory(genuine, neo)))
        // Installed by a fake F-Droid, it doesn't.
        assertEquals(StoreKeys.Verdict.UNVERIFIED, StoreKeys.verify(neo, inventory(fake, neo)))
        // Google Play installed by itself on GrapheneOS, with its rotated key.
        val play = app(
            "com.android.vending",
            installer = "com.android.vending",
            signers = setOf("7ce83c1b71f3d572fed04c8d40c5cb10ff75e6d87d9df6fbd53f0468c2905053"),
        )
        assertEquals(StoreKeys.Verdict.KEY_MATCHES, StoreKeys.verify(play, inventory(play)))
    }

    @Test
    fun `apps from a fake store are not from an app store`() = runTest {
        val fake = app("org.fdroid.fdroid", installer = "com.android.chrome", signers = setOf(otherKey))
        val payload = app("com.example.payload", installer = fake.packageName)
        val apps = inventory(fake, payload)

        assertTrue(StoreKeys.isImpostor(fake.packageName, apps))
        assertEquals(AppOrigin.SIDELOADED, originOf(payload.packageName, apps))
        val unknown = UnknownSourceAppsCheck(FakePackages(value(apps.values.toList()))).outcome()
        assertEquals(Status.FAIL, unknown.status)
        val note = unknown.evidence.single { it.value == "com.example.payload (com.example.payload)" }.note!!
        assertTrue("without its signing key" in note, note)
        // The fake store is a dropper: SUSP-5004 lists what it installed.
        assertEquals(Status.FAIL, InstalledByAppCheck(FakePackages(value(apps.values.toList()))).status())
    }

    @Test
    fun `apps from a genuine store, or one Droynis can't check, are unchanged`() = runTest {
        for (store in listOf(
            app("org.fdroid.fdroid", installer = "org.fdroid.fdroid", signers = setOf(fdroidKey)),
            app("com.aurora.store", installer = "com.aurora.store", signers = setOf(otherKey)),
            app("org.fdroid.fdroid", installer = "org.fdroid.fdroid"),
        )) {
            val organic = app("app.organicmaps", installer = store.packageName)
            val apps = inventory(store, organic)
            assertEquals(AppOrigin.STORE, originOf(organic.packageName, apps))
            assertEquals(Status.PASS, InstalledByAppCheck(FakePackages(value(apps.values.toList()))).status())
        }
        // An installer that isn't installed: Android clears it when one is uninstalled, so this is rare.
        assertEquals(AppOrigin.STORE, originOf("app.organicmaps", inventory(app("app.organicmaps", installer = "org.fdroid.fdroid"))))
    }

    @Test
    fun `SUSP-5009 store impostors`() = runTest {
        assertEquals(Status.PASS, StoreImpostorCheck(FakePackages()).status())
        assertEquals(Status.UNKNOWN, StoreImpostorCheck(FakePackages(unavailable())).status())

        val genuine = app("org.fdroid.fdroid", installer = "org.fdroid.fdroid", signers = setOf(fdroidKey))
        val pass = StoreImpostorCheck(FakePackages(value(listOf(genuine)), mapOf(genuine.packageName to "F-Droid"))).outcome()
        assertEquals(Status.PASS, pass.status)
        assertEquals("signed with F-Droid's key", pass.evidence.last().note)
        assertEquals(Trust.NOT_COUNTED, pass.evidence.last().trust)

        val fake = app("com.android.vending", installer = null, signers = setOf(otherKey))
        val labels = mapOf(fake.packageName to "Google Play Store")
        val idle = StoreImpostorCheck(FakePackages(value(listOf(fake)), labels)).outcome()
        assertEquals(Status.FAIL, idle.status)
        assertEquals("1 app uses an app store's name without its signing key: Google Play Store", idle.summary)
        assertNull(idle.escalation)

        val payload = app("com.example.payload", installer = fake.packageName)
        val dropped = StoreImpostorCheck(FakePackages(value(listOf(fake, payload)), labels)).outcome()
        assertEquals(Severity.CRITICAL, dropped.escalation)
        assertEquals("not signed with any of Google Play's keys; installed 1 app", dropped.evidence.last().note)

        // A store the user built and signed themselves: trusted, not counted.
        val trusted = StoreImpostorCheck(FakePackages(value(listOf(fake)), labels))
            .run(scanContext().copy(trustedApps = setOf(fake.packageName)))
        assertEquals(Status.PASS, trusted.status)

        val unread = app("org.fdroid.fdroid", signers = emptySet())
        assertEquals(Status.UNKNOWN, StoreImpostorCheck(FakePackages(value(listOf(unread)))).status())
    }
}
