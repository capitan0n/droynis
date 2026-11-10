package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Trust
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/** Known stalkerware and monitoring apps (SUSP-5007). */
class StalkerwareCheckTest {

    private val spyKey = "31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"
    private val ownKey = "0000000000000000000000000000000000000001"

    private val list = StalkerwareIndicators(
        listOf(
            IndicatorFamily("TheTruthSpy", IndicatorKind.STALKERWARE, listOf("com.systemservice"), listOf(spyKey)),
            IndicatorFamily("Life360", IndicatorKind.WATCHWARE, listOf("com.life360.android.safetymapd"), emptyList()),
        ),
        date = "2026-10-20",
        source = Source("test list"),
    )

    private fun footprint(pkg: String, sha1: String = ownKey, hidden: Boolean = false): AppFootprint {
        val label = pkg.substringAfterLast('.').replaceFirstChar { it.uppercase() }
        val entry = LauncherEntry(".Main", label, enabled = !hidden, turnedOff = hidden, iconCoverage = if (hidden) null else 0.8)
        return AppFootprint(pkg, label, listOf(entry), startsAtBoot = false, signerSha1 = listOf(sha1))
    }

    private fun check(vararg apps: AppFootprint) = StalkerwareCheck(
        FakeFootprints(value(apps.toList())),
        FakePackages(
            value(apps.map { InstalledApp(it.packageName, isSystem = false, isDebuggable = false, installer = null, targetSdk = 35) }),
        ),
        list,
    )

    @Test
    fun `matches by package name, by signing key or both`() {
        assertEquals("TheTruthSpy (stalkerware): same package name", list.match("com.systemservice", listOf(ownKey))?.note)
        assertEquals("TheTruthSpy (stalkerware): same signing key", list.match("com.renamed.copy", listOf(spyKey.lowercase()))?.note)
        assertEquals("TheTruthSpy (stalkerware): same package name and signing key", list.match("com.systemservice", listOf(spyKey))?.note)
        assertNull(list.match("org.fdroid.fdroid", listOf(ownKey)))
    }

    @Test
    fun `a signing key outweighs a copied package name`() {
        val match = list.match("com.life360.android.safetymapd", listOf(spyKey))
        assertEquals("TheTruthSpy", match?.family?.name)
        assertEquals(false, match?.byPackage)
    }

    @Test
    fun `no listed app passes and names the list`() = runTest {
        val outcome = check(footprint("org.fdroid.fdroid")).outcome()
        assertEquals(Status.PASS, outcome.status)
        assertEquals(StalkerwareCheck.NONE, outcome.summary)
        assertEquals("2 apps, updated 2026-10-20", outcome.evidence.single { it.label == "Indicator list" }.value)
    }

    @Test
    fun `stalkerware is critical`() = runTest {
        val outcome = check(footprint("com.renamed.copy", sha1 = spyKey, hidden = true)).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.CRITICAL, outcome.escalation)
        assertEquals("1 app matches known stalkerware: Copy", outcome.summary)
        val listed = outcome.evidence.last()
        assertEquals(Trust.COUNTED, listed.trust)
        assertTrue(listed.note!!.startsWith("TheTruthSpy (stalkerware): same signing key; turned its app drawer icon off"))
    }

    @Test
    fun `a monitoring app that doesn't hide is a warning`() = runTest {
        val outcome = check(footprint("com.life360.android.safetymapd")).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("1 known monitoring app: Safetymapd", outcome.summary)
    }

    @Test
    fun `both kinds are summed up apart`() = runTest {
        val outcome = check(footprint("com.systemservice"), footprint("com.life360.android.safetymapd")).outcome()
        assertEquals(Severity.CRITICAL, outcome.escalation)
        assertEquals("1 app matches known stalkerware: Systemservice; 1 known monitoring app: Safetymapd", outcome.summary)
    }

    @Test
    fun `a monitoring app you trust is listed but not counted`() = runTest {
        val outcome = check(footprint("com.life360.android.safetymapd"))
            .run(scanContext().copy(trustedApps = setOf("com.life360.android.safetymapd")))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust are on the list: Safetymapd", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.last().trust)
    }

    @Test
    fun `an unreadable app list is unknown, never a pass`() = runTest {
        val check = StalkerwareCheck(FakeFootprints(unavailable("no QUERY_ALL_PACKAGES")), FakePackages(), list)
        assertEquals(Status.UNKNOWN, check.status())
    }

    @Test
    fun `the bundled list loads and holds well-formed indicators`() {
        val bundled = StalkerwareIndicators.bundled
        assertTrue(bundled.size > 100, "only ${bundled.size} apps on the bundled list")
        assertTrue(Regex("""\d{4}-\d{2}-\d{2}""").matches(bundled.date))
        val sha1 = Regex("[0-9A-F]{40}")
        val packageName = Regex("""[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+""")
        for (family in StalkerwareIndicatorData.FAMILIES) {
            assertTrue(family.packages.isNotEmpty() || family.certificates.isNotEmpty(), family.name)
            family.certificates.forEach { assertTrue(sha1.matches(it), "${family.name}: $it") }
            family.packages.forEach { assertTrue(packageName.matches(it), "${family.name}: $it") }
        }
        assertEquals(IndicatorKind.STALKERWARE, bundled.match("com.systemservice", emptyList())?.family?.kind)
    }

    @Test
    fun `belongs to suspicious apps`() {
        val probes = FakeProbes()
        assertEquals(Category.SUSPICIOUS_APPS, StalkerwareCheck(probes.footprints, probes.packages).spec.category)
    }
}
