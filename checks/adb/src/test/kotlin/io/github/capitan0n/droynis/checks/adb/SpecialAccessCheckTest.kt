package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.adb.SpecialAccessCheck.Access
import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.core.Trust
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class SpecialAccessCheckTest {

    private val source = Source("dumpsys appops", Grant.SHIZUKU)
    private val context = ScanContext(
        ZonedDateTime.of(2026, 10, 5, 12, 0, 0, 0, ZoneOffset.UTC),
        sdkInt = 37,
        appPackage = "io.github.capitan0n.droynis",
    )

    private fun check(
        access: Access,
        dump: Reading<String>,
        apps: Reading<List<InstalledApp>> = Reading.Value(APPS, Source("fake")),
    ) = SpecialAccessCheck(
        access,
        dumpsys = object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump
        },
        packages = object : PackageInventory {
            override fun installedApps() = apps
            override fun label(packageName: String) = LABELS[packageName] ?: packageName
        },
    )

    private fun dump(vararg blocks: String) = Reading.Value("AppOps Uid Op State\n" + blocks.joinToString("\n"), source)

    private fun app(uid: String, pkg: String, op: String, mode: String) =
        "  Uid $uid:\n    state=cch\n    Package $pkg:\n      $op ($mode):"

    @Test
    fun `every access is an adb-tier app check with its own settings screen`() {
        val specs = Access.entries.associateWith { check(it, dump()).spec }

        assertEquals((4102..4107).map { "APPS-$it" } + "APPS-4109" + "SUSP-5103", specs.values.map { it.id })
        assertTrue(specs.values.all { it.requiredTier == Tier.ADB })
        // Settings switches are app permissions; access only adb can give is a sign of stalkerware.
        assertEquals(Category.SUSPICIOUS_APPS, specs.getValue(Access.SCREEN_CAPTURE).category)
        assertTrue(specs.filterKeys { it != Access.SCREEN_CAPTURE }.values.all { it.category == Category.APPS })
        // Each Settings switch has its own screen; screen capture has no switch, only an adb command.
        val switches = specs.filterKeys { it != Access.SCREEN_CAPTURE }.values
        assertEquals(switches.size, switches.map { it.remediation.settingsActions.single() }.toSet().size)
        val capture = specs.getValue(Access.SCREEN_CAPTURE).remediation
        assertTrue(capture.settingsActions.isEmpty())
        assertEquals("adb shell appops set <package> PROJECT_MEDIA ignore", capture.command)
        // Low-risk switches are listed but don't count in the score.
        assertEquals(
            listOf(Severity.INFO, Severity.INFO),
            listOf(Access.WRITE_SETTINGS, Access.MANAGE_MEDIA).map { specs.getValue(it).severity },
        )
    }

    @Test
    fun `per-app links open the app's own switch where Android has one, else App info`() {
        fun appActions(access: Access) = check(access, dump()).spec.remediation.appSettingsActions

        assertEquals(listOf(SettingsActions.APP_ALL_FILES_ACCESS), appActions(Access.ALL_FILES))
        assertEquals(listOf(SettingsActions.UNKNOWN_APP_SOURCES), appActions(Access.INSTALL_APPS))
        // Android 11+ ignores the package of the overlay screen; App info has the switch.
        assertTrue(appActions(Access.OVERLAY).isEmpty())
        assertTrue(appActions(Access.SCREEN_CAPTURE).isEmpty())
    }

    @Test
    fun `an app that may capture the screen without asking is a warning, linked to its settings`() = runTest {
        val outcome = check(
            Access.SCREEN_CAPTURE,
            dump(
                app("u0a10", "com.android.settings", "PROJECT_MEDIA", "allow"),
                app("u0a130", "org.example.bubbles", "PROJECT_MEDIA", "allow"),
                app("u0a132", "org.example.files", "PROJECT_MEDIA", "ignore"),
            ),
        ).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, check(Access.SCREEN_CAPTURE, dump()).spec.severity)
        assertEquals("1 app can record the screen without asking: Bubbles", outcome.summary)
        val row = outcome.evidence.single { it.label == "Screen capture without asking" }
        assertEquals("Bubbles (org.example.bubbles)", row.value)
        assertEquals("org.example.bubbles", row.packageName)
    }

    @Test
    fun `screen capture that still asks passes`() = runTest {
        // The default mode, as an app that once asked to record the screen leaves it.
        val outcome = check(
            Access.SCREEN_CAPTURE,
            dump(app("u0a130", "org.example.bubbles", "PROJECT_MEDIA", "ignore")),
        ).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app can record the screen without asking", outcome.summary)
    }

    @Test
    fun `a user app with the access fails and is named`() = runTest {
        val outcome = check(
            Access.OVERLAY,
            dump(app("u0a130", "org.example.bubbles", "SYSTEM_ALERT_WINDOW", "allow")),
        ).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app can draw over other apps: Bubbles", outcome.summary)
        assertEquals("Bubbles (org.example.bubbles)", outcome.evidence.single { it.label == "Display over other apps" }.value)
    }

    @Test
    fun `a trusted app is listed but not counted`() = runTest {
        val dump = dump(
            app("u0a130", "org.example.bubbles", "SYSTEM_ALERT_WINDOW", "allow"),
            app("u0a132", "org.example.files", "SYSTEM_ALERT_WINDOW", "allow"),
        )
        val trustBubbles = context.copy(trustedApps = setOf("org.example.bubbles"))

        val one = check(Access.OVERLAY, dump).run(trustBubbles)
        assertEquals(Status.FAIL, one.status)
        assertEquals("1 app can draw over other apps: Files", one.summary)
        val bubbles = one.evidence.single { it.packageName == "org.example.bubbles" }
        assertEquals(Trust.TRUSTED, bubbles.trust)
        assertEquals("trusted by you, not counted", bubbles.note)
        assertEquals(Trust.COUNTED, one.evidence.single { it.packageName == "org.example.files" }.trust)

        val both = check(Access.OVERLAY, dump).run(
            trustBubbles.copy(trustedApps = trustBubbles.trustedApps + "org.example.files"),
        )
        assertEquals(Status.PASS, both.status)
        assertEquals("Only apps you trust can draw over other apps: Bubbles and Files", both.summary)

        // Trust covers every access the app holds.
        val files = check(Access.ALL_FILES, dump(app("u0a130", "org.example.bubbles", "MANAGE_EXTERNAL_STORAGE", "allow")))
        assertEquals(Status.PASS, files.run(trustBubbles).status)
    }

    @Test
    fun `no grant at all passes`() = runTest {
        val outcome = check(
            Access.OVERLAY,
            dump(app("u0a130", "org.example.bubbles", "SYSTEM_ALERT_WINDOW", "ignore")),
        ).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app can draw over other apps", outcome.summary)
    }

    @Test
    fun `system apps, app stores and Droynis itself do not count`() = runTest {
        val outcome = check(
            Access.INSTALL_APPS,
            dump(
                app("u0a10", "com.android.settings", "REQUEST_INSTALL_PACKAGES", "allow"),
                app("u0a131", "org.fdroid.fdroid", "REQUEST_INSTALL_PACKAGES", "allow"),
                app("u0a132", "io.github.capitan0n.droynis", "REQUEST_INSTALL_PACKAGES", "allow"),
            ),
        ).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No user app can install other apps", outcome.summary)
        assertEquals("an app store; not counted", outcome.evidence.single { it.value!!.contains("fdroid") }.note)
    }

    @Test
    fun `a uid-wide grant is matched to the app through its uid`() = runTest {
        val outcome = check(
            Access.ALL_FILES,
            dump("  Uid u0a132:\n    state=cch\n      MANAGE_EXTERNAL_STORAGE: mode=allow"),
        ).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app can read and change all your files: Files", outcome.summary)
    }

    @Test
    fun `an app missing from the app list still counts`() = runTest {
        val outcome = check(
            Access.USAGE,
            dump(app("u10a5", "org.example.work", "GET_USAGE_STATS", "allow")),
        ).run(context)

        assertEquals(Status.FAIL, outcome.status)
    }

    @Test
    fun `without the app list a grant is unknown, never a pass`() = runTest {
        val outcome = check(
            Access.USAGE,
            dump(app("u0a130", "org.example.bubbles", "GET_USAGE_STATS", "allow")),
            apps = Reading.Unavailable("denied", Source("fake")),
        ).run(context)

        assertEquals(Status.UNKNOWN, outcome.status)
    }

    @Test
    fun `an unreadable or unrecognized dump is unknown`() = runTest {
        assertEquals(
            Status.UNKNOWN,
            check(Access.OVERLAY, Reading.Unavailable("Permission Denial", source)).run(context).status,
        )
        assertEquals(
            Status.UNKNOWN,
            check(Access.OVERLAY, dump("  Uid u0a1:\n    Package a.b:\n      SYSTEM_ALERT_WINDOW (allow): time=+1s"))
                .run(context).status,
        )
    }

    private companion object {
        val APPS = listOf(
            InstalledApp("com.android.settings", isSystem = true, isDebuggable = false, installer = null, targetSdk = 37, uid = 10010),
            InstalledApp("org.example.bubbles", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35, uid = 10130),
            InstalledApp("org.fdroid.fdroid", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35, uid = 10131),
            InstalledApp("org.example.files", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35, uid = 10132),
        )
        val LABELS = mapOf(
            "org.example.bubbles" to "Bubbles",
            "org.example.files" to "Files",
            "org.fdroid.fdroid" to "F-Droid",
        )
    }

    @Test
    fun `an app exempt from unused-app permission removal is listed for information`() = runTest {
        val spec = check(Access.UNUSED_APPS, dump()).spec
        assertEquals(Severity.INFO, spec.severity)
        assertEquals(30, spec.minSdk)

        // Settings sets a uid mode, the installer API a package mode; `ignore` is the exemption either way.
        val uidWide = "  Uid u0a201:\n    state=cch\n      AUTO_REVOKE_PERMISSIONS_IF_UNUSED: mode=ignore\n    Package org.example.tracker:"
        val outcome = check(
            Access.UNUSED_APPS,
            dump(
                uidWide,
                app("u0a202", "org.example.notes", "AUTO_REVOKE_PERMISSIONS_IF_UNUSED", "ignore"),
                app("u0a203", "org.example.other", "AUTO_REVOKE_PERMISSIONS_IF_UNUSED", "allow"),
            ),
            apps = Reading.Value(
                listOf("org.example.tracker" to 10201, "org.example.notes" to 10202, "org.example.other" to 10203).map { (pkg, uid) ->
                    InstalledApp(pkg, isSystem = false, isDebuggable = false, installer = "org.fdroid.fdroid", targetSdk = 35, uid = uid)
                },
                Source("fake"),
            ),
        ).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(
            "2 apps can keep permissions while unused: org.example.tracker and org.example.notes",
            outcome.summary,
        )
        val rows = outcome.evidence.filter { it.label == "Keeps permissions while unused" }
        assertEquals(listOf("org.example.tracker", "org.example.notes"), rows.map { it.packageName })
        assertTrue(rows.all { it.trust == Trust.COUNTED })
    }

    @Test
    fun `apps left at the default keep their permission removal and pass`() = runTest {
        val outcome = check(Access.UNUSED_APPS, dump(app("u0a203", "org.example.other", "SYSTEM_ALERT_WINDOW", "allow"))).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No app can keep permissions while unused", outcome.summary)
    }
}
