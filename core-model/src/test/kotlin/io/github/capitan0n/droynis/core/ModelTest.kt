package io.github.capitan0n.droynis.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ModelTest {

    @Test
    fun `check ids must follow the AREA-NNNN format`() {
        assertFailsWith<IllegalArgumentException> { spec(id = "lock-screen") }
        assertFailsWith<IllegalArgumentException> { spec(id = "ACCS-21") }
        spec(id = "ACCS-2001")
    }

    @Test
    fun `checks cannot claim a minSdk below the app's`() {
        assertFailsWith<IllegalArgumentException> { spec(minSdk = 23) }
    }

    @Test
    fun `required tier is the highest tier among required grants`() {
        assertEquals(Tier.BASE, spec().requiredTier)
        assertEquals(Tier.ADB, spec(requires = setOf(Grant.PACKAGE_USAGE_STATS)).requiredTier)
        assertEquals(Tier.ADB, spec(requires = setOf(Grant.PACKAGE_USAGE_STATS, Grant.READ_LOGS)).requiredTier)
        assertEquals(Tier.SHIZUKU, spec(requires = setOf(Grant.DUMP, Grant.SHIZUKU)).requiredTier)
    }

    @Test
    fun `capabilities report the grants a check still lacks`() {
        val capabilities = Capabilities(setOf(Grant.DUMP))

        assertEquals(Tier.ADB, capabilities.tier)
        assertEquals(setOf(Grant.READ_LOGS), capabilities.missingFor(spec(requires = setOf(Grant.DUMP, Grant.READ_LOGS))))
        assertEquals(Tier.BASE, Capabilities().tier)
    }

    @Test
    fun `shizuku covers the adb grants, but adb grants never cover shizuku`() {
        val adbCheck = spec(requires = setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS))
        val shizukuCheck = spec(requires = setOf(Grant.SHIZUKU))

        assertEquals(emptySet(), Capabilities(setOf(Grant.SHIZUKU)).missingFor(adbCheck))
        assertEquals(setOf(Grant.SHIZUKU), Capabilities(setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS)).missingFor(shizukuCheck))
        assertEquals(Tier.SHIZUKU, Capabilities(setOf(Grant.SHIZUKU)).tier)
    }

    @Test
    fun `adb commands name the permission behind a grant`() {
        assertEquals(
            "adb shell pm grant org.example android.permission.DUMP",
            Grant.DUMP.adbGrantCommand("org.example"),
        )
        assertEquals(
            "adb shell pm revoke org.example android.permission.PACKAGE_USAGE_STATS",
            Grant.PACKAGE_USAGE_STATS.adbRevokeCommand("org.example"),
        )
        assertEquals(null, Grant.SHIZUKU.adbGrantCommand("org.example"))
    }

    @Test
    fun `readings become evidence that keeps the reason for a missing value`() {
        val source = Source("Settings.Global \"adb_enabled\"")

        assertEquals(Evidence("adb", "1", source), Reading.Value("1", source).toEvidence("adb"))
        val missing = Reading.Unavailable("not set", source).toEvidence("adb")
        assertNull(missing.value)
        assertEquals("not readable: not set", missing.note)
        assertEquals("not supported: needs API 29", Reading.Unsupported("needs API 29", source).toEvidence("adb").note)
    }

    @Test
    fun `a reading without a value never evaluates to PASS`() {
        val source = Source("fake")
        val pass = { _: Boolean -> Outcome.pass("fine") }

        assertEquals(Status.PASS, Reading.Value(true, source).evaluate("State", emptyList(), pass).status)
        assertEquals(Status.UNKNOWN, Reading.Unavailable("denied", source).evaluate("State", emptyList(), pass).status)
        assertEquals(Status.UNSUPPORTED, Reading.Unsupported("API 29", source).evaluate("State", emptyList(), pass).status)
    }

    @Test
    fun `sources name the grant they used`() {
        assertEquals("dumpsys device_policy (via DUMP)", Source("dumpsys device_policy", Grant.DUMP).toString())
        assertEquals(Tier.ADB, Source("dumpsys device_policy", Grant.DUMP).tier)
        assertEquals(Tier.BASE, Source("KeyguardManager.isDeviceSecure()").tier)
    }

    private fun spec(
        id: String = "TEST-0001",
        minSdk: Int = CheckSpec.MIN_SDK,
        requires: Set<Grant> = emptySet(),
    ) = CheckSpec(
        id = id,
        category = Category.ACCESS_CONTROL,
        title = "Test check",
        severity = Severity.NOTICE,
        explanation = "Why it matters.",
        remediation = Remediation("Fix it."),
        minSdk = minSdk,
        requires = requires,
    )
}
