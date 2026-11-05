package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.AppFootprint
import io.github.capitan0n.droynis.checks.base.AppFootprintProbe
import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.LauncherEntry
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
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

/** `dumpsys activity services` (ServicesDump) and hidden apps running in the background (SUSP-5101). */
class HiddenBackgroundCheckTest {

    // ServicesDump

    @Test
    fun `reads active services with their foreground and started flags`() {
        val parsed = assertIs<ServicesDump.Result.Parsed>(ServicesDump.parse(SERVICES))

        assertEquals(
            listOf(
                RunningService(0, "com.android.bluetooth", ".btservice.AdapterService", foreground = false, started = true),
                RunningService(0, "x.ads", ".AdService", foreground = true, started = true),
                RunningService(0, "a.keyboard", ".ImeService", foreground = false, started = false),
                RunningService(0, "a.plugin", "a.plugin.work.SyncService", foreground = false, started = true),
                RunningService(10, "x.other", ".Svc", foreground = false, started = true),
            ),
            parsed.services,
        )
    }

    @Test
    fun `restarting services and their flags don't join the active ones`() {
        val parsed = assertIs<ServicesDump.Result.Parsed>(ServicesDump.parse(SERVICES))
        assertTrue(parsed.services.none { it.packageName == "b.restart" })
        // The restarting record's startRequested=true must not land on x.other, the record before it.
        assertEquals(true, parsed.services.single { it.packageName == "x.other" }.started)
        val onlyBound = SERVICES.replace(
            "    startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=1\n\n  Restarting",
            "\n  Restarting",
        )
        val other = assertIs<ServicesDump.Result.Parsed>(ServicesDump.parse(onlyBound)).services.single { it.packageName == "x.other" }
        assertEquals(false, other.started)
    }

    @Test
    fun `a record line in another shape fails the parse`() {
        val garbled = SERVICES.replace("ServiceRecord{d4e5f6 u0 x.ads/.AdService c:x.ads}", "ServiceRecord{d4e5f6 x.ads}")
        val failed = assertIs<ServicesDump.Result.Failed>(ServicesDump.parse(garbled))
        assertEquals("1 service records in an unexpected format", failed.reason)
    }

    @Test
    fun `other output, or none, fails the parse`() {
        assertIs<ServicesDump.Result.Failed>(ServicesDump.parse("AppOps Uid Op State\n  Uid u0a1:"))
        assertIs<ServicesDump.Result.Failed>(ServicesDump.parse("ACTIVITY MANAGER SERVICES (dumpsys activity services)\n  (nothing)"))
    }

    // SUSP-5101

    @Test
    fun `needs the adb tier and belongs to suspicious apps`() {
        val spec = check().spec
        assertEquals("SUSP-5101", spec.id)
        assertEquals(Category.SUSPICIOUS_APPS, spec.category)
        assertEquals(setOf(Grant.DUMP, Grant.PACKAGE_USAGE_STATS), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(29, spec.minSdk)
    }

    @Test
    fun `a hidden sideloaded app running a foreground service is critical`() = runTest {
        val outcome = check().run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(Severity.CRITICAL, outcome.escalation)
        assertEquals("1 hidden app running in the background: Ads", outcome.summary)
        val ads = outcome.evidence.single { it.packageName == "x.ads" }
        assertEquals("Ads (x.ads)", ads.value)
        assertEquals(
            "runs a foreground service now, started a foreground service 3 h ago, drew over other apps 2 h ago; " +
                "turned its app drawer icon off after it was installed; installed from outside an app store",
            ads.note,
        )
        // The plugin from a store is listed, not counted; the keyboard is only bound, the visible app ignored.
        assertEquals(
            "runs a service it started; no app drawer icon; from an app store; not counted",
            outcome.evidence.single { it.packageName == "a.plugin" }.note,
        )
        assertTrue(outcome.evidence.none { it.packageName in setOf("a.keyboard", "org.signal", "x.other") })
    }

    @Test
    fun `a trusted app is listed but not counted`() = runTest {
        val outcome = check().run(context.copy(trustedApps = setOf("x.ads")))
        assertEquals(Status.PASS, outcome.status)
        assertEquals(
            "Only hidden apps you trust run in the background: Ads (1 add-on without an icon of its own listed, not counted)",
            outcome.summary,
        )
        assertEquals(Trust.TRUSTED, outcome.evidence.single { it.packageName == "x.ads" }.trust)
        assertEquals(Trust.NOT_COUNTED, outcome.evidence.single { it.packageName == "a.plugin" }.trust)
    }

    @Test
    fun `another user's services don't count for this one`() = runTest {
        val outcome = check(apps = listOf(footprint("x.other", entries = emptyList()) to app("x.other", installer = null)))
            .run(context)
        assertEquals(Status.PASS, outcome.status)
        assertEquals("No hidden app runs in the background", outcome.summary)
    }

    @Test
    fun `only add-ons from a store running pass, listed`() = runTest {
        val outcome = check(apps = listOf(footprint("a.plugin", entries = emptyList()) to app("a.plugin"))).run(context)
        assertEquals(Status.PASS, outcome.status)
        assertEquals("No hidden app runs in the background (1 add-on without an icon of its own listed, not counted)", outcome.summary)
    }

    @Test
    fun `app-ops history older than 7 days doesn't count`() = runTest {
        val outcome = check(
            apps = listOf(footprint("x.old", entries = emptyList()) to app("x.old", installer = null)),
            appops = appops(access("x.old", "SYSTEM_ALERT_WINDOW", "-8d0h0m0s0ms")),
        ).run(context)
        assertEquals(Status.PASS, outcome.status)
    }

    @Test
    fun `with nothing out of sight the dumps aren't read`() = runTest {
        val asked = mutableListOf<String>()
        val outcome = check(apps = listOf(footprint("org.signal") to app("org.signal")), asked = asked).run(context)
        assertEquals(Status.PASS, outcome.status)
        assertEquals("Every app you installed has a visible app drawer icon", outcome.summary)
        assertEquals(emptyList(), asked)
    }

    @Test
    fun `one unreadable dump is unknown unless the other shows something`() = runTest {
        val denied = Reading.Unavailable("Permission Denial", Source("dumpsys activity services", Grant.DUMP))
        val quiet = check(
            apps = listOf(footprint("x.old", entries = emptyList()) to app("x.old", installer = null)),
            services = denied,
        ).run(context)
        assertEquals(Status.UNKNOWN, quiet.status)
        assertEquals("No hidden app was seen running, but running services could not be read", quiet.summary)

        val seen = check(services = denied).run(context)
        assertEquals(Status.FAIL, seen.status)
        assertEquals(
            "started a foreground service 3 h ago, drew over other apps 2 h ago; " +
                "turned its app drawer icon off after it was installed; installed from outside an app store",
            seen.evidence.single { it.packageName == "x.ads" }.note,
        )
    }

    @Test
    fun `an app list that can't be read is unknown`() = runTest {
        val outcome = HiddenBackgroundCheck(
            dumpsys(Reading.Value(SERVICES, SOURCE), appops(), mutableListOf()),
            object : AppFootprintProbe {
                override fun userApps() = Reading.Unavailable("binder died", Source("fake"))
            },
            inventory(emptyList()),
        ).run(context)
        assertEquals(Status.UNKNOWN, outcome.status)
        assertNull(outcome.escalation)
    }

    private val context = ScanContext(
        ZonedDateTime.of(2026, 10, 5, 12, 0, 0, 0, ZoneOffset.UTC),
        sdkInt = 37,
        appUid = 10_123,
    )

    private fun check(
        apps: List<Pair<AppFootprint, InstalledApp>> = DEFAULT_APPS,
        services: Reading<String> = Reading.Value(SERVICES, SOURCE),
        appops: Reading<String> = appops(
            access("x.ads", "START_FOREGROUND", "-3h0m0s0ms"),
            access("x.ads", "SYSTEM_ALERT_WINDOW", "-2h0m0s0ms"),
        ),
        asked: MutableList<String> = mutableListOf(),
    ) = HiddenBackgroundCheck(
        dumpsys(services, appops, asked),
        object : AppFootprintProbe {
            override fun userApps() = Reading.Value(apps.map { it.first }, Source("fake"))
        },
        inventory(apps.map { it.second }),
    )

    private fun dumpsys(services: Reading<String>, appops: Reading<String>, asked: MutableList<String>) = object : Dumpsys {
        override fun dump(service: String, vararg args: String): Reading<String> {
            val command = (listOf(service) + args).joinToString(" ")
            asked += command
            return when (command) {
                "activity services" -> services
                "appops" -> appops
                else -> error("unexpected dumpsys $command")
            }
        }
    }

    private fun inventory(apps: List<InstalledApp>) = object : PackageInventory {
        override fun installedApps() = Reading.Value(apps, Source("fake"))
        override fun label(packageName: String) = packageName
    }

    private fun appops(vararg blocks: Array<String>) =
        Reading.Value("AppOps Uid Op State\n" + blocks.flatMap { it.toList() }.joinToString("\n"), Source("dumpsys appops", Grant.DUMP))

    private fun access(pkg: String, op: String, ago: String) = arrayOf(
        "  Uid u0a${pkg.length}:",
        "    Package $pkg:",
        "      $op (allow):",
        "        null=[",
        "          Access: [bg-s] 2026-10-05 09:00:00.000 ($ago)",
        "        ]",
    )

    private companion object {
        val SOURCE = Source("dumpsys activity services", Grant.DUMP)

        fun app(pkg: String, installer: String? = "org.fdroid.fdroid") =
            InstalledApp(pkg, isSystem = false, isDebuggable = false, installer = installer, targetSdk = 35)

        fun footprint(
            pkg: String,
            label: String = pkg.substringAfterLast('.').replaceFirstChar { it.uppercase() },
            entries: List<LauncherEntry> = listOf(LauncherEntry(".Main", label, enabled = true, iconCoverage = 0.8)),
        ) = AppFootprint(pkg, label, entries, startsAtBoot = false)

        val DEFAULT_APPS = listOf(
            footprint("x.ads", entries = listOf(LauncherEntry(".Main", "Ads", enabled = false, turnedOff = true))) to
                app("x.ads", installer = "com.google.android.packageinstaller"),
            footprint("a.keyboard", entries = emptyList()) to app("a.keyboard"),
            footprint("a.plugin", entries = emptyList()) to app("a.plugin"),
            footprint("org.signal") to app("org.signal"),
            footprint("x.other", entries = emptyList()) to app("x.other", installer = null),
        )

        /** Shaped like ActiveServices' dump in Android 17, trimmed to the lines that matter. */
        val SERVICES = """
            ACTIVITY MANAGER SERVICES (dumpsys activity services)
              User 0 active services:
              * ServiceRecord{a1b2c3 u0 com.android.bluetooth/.btservice.AdapterService}
                intent={cmp=com.android.bluetooth/.btservice.AdapterService}
                packageName=com.android.bluetooth
                processName=com.android.bluetooth
                baseDir=/system/app/Bluetooth/Bluetooth.apk
                dataDir=/data/user_de/0/com.android.bluetooth
                app=ProcessRecord{c5b4d8a 2096:com.android.bluetooth/1002}
                createTime=-6d20h33m10s386ms startingBgTimeout=--
                lastActivity=-6d20h33m10s384ms restartTime=-6d20h33m10s384ms createdFromFg=true
                startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=1
              * ServiceRecord{d4e5f6 u0 x.ads/.AdService c:x.ads}
                intent={cmp=x.ads/.AdService}
                packageName=x.ads
                processName=x.ads
                app=ProcessRecord{1a2b3c 12345:x.ads/u0a250}
                isForeground=true foregroundId=7 types=0x00000000 foregroundNoti=Notification(channel=ads shortcut=null contentView=null vibrate=null sound=null defaults=0x0 flags=0x62 color=0x00000000 vis=PRIVATE)
                createTime=-2h3m4s5ms startingBgTimeout=--
                lastActivity=-1m2s3ms restartTime=-2h3m4s5ms createdFromFg=false
                startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=3
              * ServiceRecord{0a0b0c u0 a.keyboard/.ImeService}
                intent={act=android.view.InputMethod cmp=a.keyboard/.ImeService}
                packageName=a.keyboard
                permission=android.permission.BIND_INPUT_METHOD
                createTime=-1h0m0s0ms startingBgTimeout=--
                Bindings:
                * IntentBindRecord{5e6f7a CREATE}:
                  intent={act=android.view.InputMethod cmp=a.keyboard/.ImeService}
                  requested=true received=true hasBound=true doRebind=false
              * ServiceRecord{0b0c0d u0 a.plugin/a.plugin.work.SyncService}
                packageName=a.plugin
                startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=2
              User 10 active services:
              * ServiceRecord{0d0e0f u10 x.other/.Svc}
                packageName=x.other
                startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=1

              Restarting services:
              * Restarting ServiceRecord{1f2e3d u0 b.restart/.Svc}
                packageName=b.restart
                startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=1

              Connection bindings to services:
              * ConnectionRecord{2a3b4c u0 CR a.keyboard/.ImeService:@5e6f7a}
                binding=AppBindRecord{6c7d8e a.keyboard/.ImeService:system}
        """.trimIndent() + "\n"
    }
}
