package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.DefaultAppsProbe
import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import io.github.capitan0n.droynis.core.Trust
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

/** Background SMS, call log and contacts use (SUSP-5104). */
class BackgroundDataUseCheckTest {

    private val context = ScanContext(ZonedDateTime.of(2026, 10, 5, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun check(
        vararg blocks: Array<String>,
        sms: String? = "com.google.android.apps.messaging",
        phone: String? = "com.google.android.dialer",
        apps: Reading<List<InstalledApp>> = Reading.Value(APPS, Source("fake")),
    ) = BackgroundDataUseCheck(
        dumpsys = object : Dumpsys {
            override fun dump(service: String, vararg args: String): Reading<String> {
                assertEquals("appops", service)
                return Reading.Value("AppOps Uid Op State\n" + blocks.flatMap { it.toList() }.joinToString("\n"), SOURCE)
            }
        },
        packages = object : PackageInventory {
            override fun installedApps() = apps
            override fun label(packageName: String) = LABELS[packageName] ?: packageName
        },
        defaults = object : DefaultAppsProbe {
            override fun smsApp() = Reading.Value(sms, Source("fake"))
            override fun phoneApp() = Reading.Value(phone, Source("fake"))
        },
    )

    private fun access(pkg: String, op: String, state: String, ago: String) = arrayOf(
        "  Uid u0a${pkg.length}:",
        "    Package $pkg:",
        "      $op (allow):",
        "        null=[",
        "          Access: [$state-s] 2026-10-05 11:00:00.000 ($ago)",
        "        ]",
    )

    @Test
    fun `needs the adb tier and belongs to suspicious apps`() {
        val spec = check().spec
        assertEquals("SUSP-5104", spec.id)
        assertEquals(Category.SUSPICIOUS_APPS, spec.category)
        assertEquals(setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
    }

    @Test
    fun `foreground use and old records pass`() = runTest {
        val outcome = check(
            access("org.kde.kdeconnect_tp", "READ_SMS", "top", "-1h0m0s0ms"),
            access("org.kde.kdeconnect_tp", "READ_CONTACTS", "bg", "-8d0h0m0s0ms"),
        ).run(context)
        assertEquals(Status.PASS, outcome.status)
        assertEquals(BackgroundDataUseCheck.NONE, outcome.summary)
    }

    @Test
    fun `the default SMS and phone apps pass for their role`() = runTest {
        val outcome = check(
            access("com.google.android.apps.messaging", "RECEIVE_SMS", "bg", "-5m0s0ms"),
            access("com.google.android.apps.messaging", "READ_CONTACTS", "bg", "-5m0s0ms"),
            access("com.google.android.dialer", "READ_CALL_LOG", "cch", "-2h0m0s0ms"),
        ).run(context)
        assertEquals(Status.PASS, outcome.status)
    }

    @Test
    fun `the SMS app reading the call log still counts`() = runTest {
        val outcome = check(access("com.google.android.apps.messaging", "READ_CALL_LOG", "bg", "-5m0s0ms")).run(context)
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app used the call log from the background: Messages", outcome.summary)
    }

    @Test
    fun `a sideloaded default SMS app is not explained by its role`() = runTest {
        val outcome = check(access("com.sms.stealer", "RECEIVE_SMS", "bg", "-1h0m0s0ms"), sms = "com.sms.stealer").run(context)
        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.WARNING, outcome.escalation)
        assertEquals("received an SMS 1 h ago, in the background", outcome.evidence.last().note)
    }

    @Test
    fun `a store app reading data in the background is a notice, listed per kind`() = runTest {
        val outcome = check(
            access("org.kde.kdeconnect_tp", "READ_SMS", "bg", "-3h0m0s0ms"),
            access("org.kde.kdeconnect_tp", "READ_CONTACTS", "cch", "-1h0m0s0ms"),
        ).run(context)
        assertEquals(Status.FAIL, outcome.status)
        assertNull(outcome.escalation)
        assertEquals("1 app used SMS and contacts from the background: KDE Connect", outcome.summary)
        assertEquals(listOf("SMS", "Contacts"), outcome.evidence.drop(1).map { it.label })
        assertEquals("read contacts 1 h ago, cached in the background", outcome.evidence.last().note)
    }

    @Test
    fun `a trusted app is listed, not counted`() = runTest {
        val outcome = check(access("org.kde.kdeconnect_tp", "READ_SMS", "bg", "-3h0m0s0ms"))
            .run(context.copy(trustedApps = setOf("org.kde.kdeconnect_tp")))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Only apps you trust used SMS, the call log or contacts from the background: KDE Connect", outcome.summary)
        assertEquals(Trust.TRUSTED, outcome.evidence.last().trust)
    }

    @Test
    fun `system apps don't count and an unreadable app list is unknown`() = runTest {
        assertEquals(Status.PASS, check(access("com.android.phone", "READ_CONTACTS", "bg", "-5m0s0ms")).run(context).status)
        val unreadable = check(
            access("org.kde.kdeconnect_tp", "READ_SMS", "bg", "-3h0m0s0ms"),
            apps = Reading.Unavailable("binder died", Source("fake")),
        )
        assertEquals(Status.UNKNOWN, unreadable.run(context).status)
    }

    private companion object {
        val SOURCE = Source("dumpsys appops", Grant.DUMP)

        val APPS = listOf(
            InstalledApp("com.google.android.apps.messaging", false, false, "com.android.vending", 36),
            InstalledApp("com.google.android.dialer", false, false, "com.android.vending", 36),
            InstalledApp("org.kde.kdeconnect_tp", false, false, "org.fdroid.fdroid", 36),
            InstalledApp("com.sms.stealer", false, false, "com.google.android.packageinstaller", 30),
            InstalledApp("com.android.phone", true, false, null, 37),
        )
        val LABELS = mapOf(
            "com.google.android.apps.messaging" to "Messages",
            "org.kde.kdeconnect_tp" to "KDE Connect",
        )
    }
}
