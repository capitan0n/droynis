package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.lang.reflect.Proxy
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

/** Quick Share visibility (NETW-3302). */
class QuickShareCheckTest {

    private val source = Source("su", Grant.ROOT)
    private val context = ScanContext(ZonedDateTime.of(2026, 11, 15, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 36)

    private fun gms(enabled: Boolean = true) =
        InstalledApp(QuickShareCheck.GMS, isSystem = true, isDebuggable = false, installer = null, targetSdk = 36, isEnabled = enabled)

    private val samsung =
        InstalledApp(QuickShareCheck.SAMSUNG, isSystem = true, isDebuggable = false, installer = null, targetSdk = 36)

    private val unlisted: Reading<List<InstalledApp>> = Reading.Unavailable("denied", Source("fake"))

    private fun packages(vararg apps: InstalledApp): PackageInventory = packages(Reading.Value(apps.toList(), Source("fake")))

    private fun packages(apps: Reading<List<InstalledApp>>) = object : PackageInventory {
        override fun installedApps() = apps
        override fun label(packageName: String) = packageName
    }

    /** A root shell that answers only the Quick Share read and fails on any other. */
    private fun root(settings: Reading<String?>): RootShellProbe {
        val unused = Proxy.newProxyInstance(RootShellProbe::class.java.classLoader, arrayOf(RootShellProbe::class.java)) { _, method, _ ->
            error("the check called ${method.name}")
        } as RootShellProbe
        return object : RootShellProbe by unused {
            override fun quickShareSettings() = settings
        }
    }

    /** One SharedPreferences file the way Android writes it, after its header line. */
    private fun prefs(vararg entries: String, name: String = "nearbysharing:service:state.xml") =
        "${QuickSharePrefs.FILE}$name\n<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n" +
            entries.joinToString("") { "    $it\n" } + "</map>\n"

    private fun int(name: String, value: Int) = """<int name="$name" value="$value" />"""

    private fun string(name: String, value: String) = """<string name="$name">$value</string>"""

    private val device = string("device_name", "Alexandros&apos; Pixel")

    private suspend fun outcome(output: String?, apps: PackageInventory = packages(gms())) =
        QuickShareCheck(root(Reading.Value(output, source)), apps).run(context)

    @Test
    fun `Everyone fails, keeping no device name`() = runTest {
        val outcome = outcome(prefs(device, int("device_visibility", 4)))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("Quick Share is visible to everyone nearby", outcome.summary)
        assertEquals("Everyone", outcome.evidence.first().value)
        assertEquals("stored as 4", outcome.evidence.first().note)
        assertTrue(outcome.evidence.none { "Pixel" in "${it.value} ${it.note}" })
        val where = outcome.evidence.single { it.label == "Read from" }
        assertTrue(where.personal)
        assertEquals("nearbysharing:service:state.xml", where.value)
        assertEquals("device_visibility", where.note)
    }

    @Test
    fun `the 10-minute Everyone mode is named, and companions never decide`() = runTest {
        val timed = outcome(
            prefs(
                int("nearby_sharing.background_visibility", 4),
                int("nearby_sharing.background_fallback_visibility", 3),
                """<long name="nearby_sharing.background_visibility_expiration_seconds" value="1763208000" />""",
            ),
        )
        assertEquals(Status.FAIL, timed.status)
        assertEquals("may be temporary", timed.evidence.single { it.label == "Everyone" }.value)

        // A fallback of Everyone isn't the setting in force.
        val fallback = outcome(prefs(int("visibility", 3), int("fallback_visibility", 4)))
        assertEquals(Status.PASS, fallback.status)
        assertEquals("Quick Share isn't visible to everyone nearby", fallback.summary)
        assertEquals("not Everyone", fallback.evidence.first().value)
    }

    @Test
    fun `numbers that are never Everyone pass, names say which mode`() = runTest {
        for (value in 1..3) {
            assertEquals(Status.PASS, outcome(prefs(int("device_visibility", value))).status, "stored as $value")
        }
        val named = mapOf(
            "DEVICE_VISIBILITY_SELF_SHARE" to "Quick Share is visible to your own devices only",
            "ALL_CONTACTS" to "Quick Share is visible to your contacts only",
            "hidden" to "Quick Share is hidden from everyone",
            "DEVICE_VISIBILITY_SELECTED_CONTACTS" to "Quick Share is visible to some of your contacts only",
        )
        for ((stored, summary) in named) {
            assertEquals(summary, outcome(prefs(string("device_visibility", stored))).summary, stored)
        }
        assertEquals(Status.FAIL, outcome(prefs(string("visibility", "DEVICE_VISIBILITY_EVERYONE"))).status)
        assertEquals(Status.FAIL, outcome(prefs(string("visibility", "4"))).status)
    }

    @Test
    fun `a value Droynis doesn't know, or settings that disagree, are unknown`() = runTest {
        for (value in listOf(0, 5, -1, 42)) {
            assertEquals(Status.UNKNOWN, outcome(prefs(int("device_visibility", value))).status, "stored as $value")
        }
        assertEquals(Status.UNKNOWN, outcome(prefs(string("device_visibility", "FRIENDS"))).status)

        val disagree = outcome(prefs(int("device_visibility", 3)) + prefs(int("visibility", 4), name = "nearbysharing:account.xml"))
        assertEquals(Status.UNKNOWN, disagree.status)
        assertEquals("Quick Share's settings disagree about its visibility", disagree.summary)

        // Two keys in one file, too.
        assertEquals(Status.UNKNOWN, outcome(prefs(int("device_visibility", 3), int("visibility", 4))).status)
        // Agreeing files are fine.
        assertEquals(Status.PASS, outcome(prefs(int("device_visibility", 3)) + prefs(int("visibility", 1), name = "nearbysharing:b.xml")).status)
    }

    @Test
    fun `no setting, no file, no folder or no read is unknown`() = runTest {
        val noKey = outcome(prefs(device, """<boolean name="enabled" value="true" />"""))
        assertEquals(Status.UNKNOWN, noKey.status)
        assertEquals("Quick Share's visibility isn't where Droynis looks for it", noKey.summary)
        assertEquals("keys: device_name, enabled", noKey.evidence.single { it.label == "Read from" }.note)

        assertEquals(Status.UNKNOWN, outcome(prefs().replace("<map>\n</map>", "<map />")).status)
        assertEquals("Quick Share has no settings file: open its settings once, then scan again", outcome("").summary)
        assertEquals("Google Play services keeps no settings for this user", outcome(null).summary)
        assertEquals(
            Status.UNKNOWN,
            QuickShareCheck(root(Reading.Unavailable("permission denied", source)), packages(gms())).run(context).status,
        )
    }

    @Test
    fun `the parser never skips what it can't read`() {
        fun failed(output: String) = assertIs<QuickSharePrefs.Result.Failed>(QuickSharePrefs.parse(output), output)

        // A cut file may have lost the entry in force.
        failed(prefs(int("device_visibility", 3)).removeSuffix("</map>\n"))
        // Entries in a shape the patterns don't take apart.
        failed(prefs("""<int value="4" name="device_visibility" />"""))
        failed(prefs("""<string name="device_visibility"><![CDATA[EVERYONE]]></string>"""))
        // The same key twice, the same file twice, text before the first file, an odd file name.
        failed(prefs(int("device_visibility", 3), int("device_visibility", 4)))
        failed(prefs(int("visibility", 3)) + prefs(int("visibility", 3)))
        failed("stray\n" + prefs(int("visibility", 3)))
        failed(prefs(int("visibility", 3), name = "../../x.xml"))
        // A value that fakes a new file cuts the real one short.
        failed(prefs(string("device_name", "x\n${QuickSharePrefs.FILE}y.xml\n<map>"), int("visibility", 4)))
    }

    @Test
    fun `Samsung's Quick Share keeps its own setting`() = runTest {
        val both = outcome(prefs(int("device_visibility", 3)), packages(gms(), samsung))
        assertEquals(Status.UNKNOWN, both.status)
        assertEquals(QuickShareCheck.SAMSUNG, both.evidence.single { it.label == "Samsung Quick Share" }.packageName)

        // Google's own Everyone still fails.
        assertEquals(Status.FAIL, outcome(prefs(int("device_visibility", 4)), packages(gms(), samsung)).status)
        // Samsung alone: nothing to read.
        assertEquals(Status.UNKNOWN, QuickShareCheck(root(Reading.Value(null, source)), packages(samsung)).run(context).status)
    }

    @Test
    fun `no Quick Share app is N-A, and an unreadable app list never passes`() = runTest {
        assertEquals(Status.UNSUPPORTED, QuickShareCheck(root(Reading.Value(null, source)), packages()).run(context).status)
        val off = QuickShareCheck(root(Reading.Value(null, source)), packages(gms(enabled = false))).run(context)
        assertEquals(Status.UNSUPPORTED, off.status)
        assertEquals("Google Play services is turned off and Samsung's Quick Share isn't installed", off.summary)

        assertEquals(Status.UNKNOWN, outcome(prefs(int("device_visibility", 3)), packages(unlisted)).status)
        assertEquals(Status.FAIL, outcome(prefs(int("device_visibility", 4)), packages(unlisted)).status)
    }
}
