package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.Keyguard
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class RootChecksTest {

    private val source = Source("su", Grant.ROOT)
    private val context = ScanContext(
        ZonedDateTime.of(2026, 10, 6, 12, 0, 0, 0, ZoneOffset.UTC),
        sdkInt = 36,
        appPackage = "io.github.capitan0n.droynis",
        appUid = 10132,
    )

    private fun <T> v(value: T): Reading<T> = Reading.Value(value, source)

    private class FakeRoot(
        var keys: Reading<String?> = Reading.Value(null, Source("su")),
        var modules: Reading<String> = Reading.Value("", Source("su")),
        var manager: Reading<RootManager> = Reading.Value(RootManager.MAGISK, Source("su")),
        var policies: Reading<String> = Reading.Value("", Source("su")),
        var settings: Reading<String> = Reading.Value("", Source("su")),
        var version: Reading<Int> = Reading.Value(30700, Source("su")),
        var tapjack: Reading<Boolean> = Reading.Value(true, Source("test")),
        var lsp: Reading<String> = Reading.Unsupported("not installed", Source("test")),
        var strings: Reading<String> = Reading.Value("", Source("su")),
        var bootScripts: Reading<String> = Reading.Value("", Source("su")),
        var tempFiles: Reading<String> = Reading.Value("", Source("su")),
        var net: Map<ProcNet, Reading<String>> = ProcNet.entries.associateWith { Reading.Value(HEADER, Source("su")) },
        var premiumSms: Reading<String?> = Reading.Value(null, Source("su")),
        var quickShare: Reading<String?> = Reading.Value(null, Source("su")),
    ) : RootShellProbe {
        override fun adbKeys() = keys
        override fun modules() = modules
        override fun manager() = manager
        override fun magiskVersion() = version
        override fun zygiskDefault() = Reading.Value(false, Source("test"))
        override fun tapjackingProtection() = tapjack
        override fun lsposed() = lsp
        override fun magiskPolicies() = policies
        override fun magiskSettings() = settings
        override fun magiskStrings() = strings
        override fun bootScripts() = bootScripts
        override fun tempFiles() = tempFiles
        override fun procNet(table: ProcNet) = net.getValue(table)
        override fun premiumSmsPolicy() = premiumSms
        override fun quickShareSettings() = quickShare
    }

    private fun lock(secure: Boolean = true) = object : Keyguard {
        override fun isDeviceSecure() = v(secure)
        override fun passwordComplexity() = error("unused")
    }

    private val packages = object : PackageInventory {
        override fun installedApps(): Reading<List<InstalledApp>> = Reading.Value(APPS, Source("fake"))
        override fun label(packageName: String) = LABELS[packageName] ?: packageName
    }

    @Test
    fun `every root check needs the root tier`() {
        val specs = rootChecks(
            object : RootProbes {
                override val keyguard = lock()
                override val root = FakeRoot()
                override val packages = this@RootChecksTest.packages
            },
        ).map { it.spec }

        assertEquals(
            listOf("INTG-1301", "INTG-1302", "INTG-1303", "ACCS-2301", "ACCS-2302", "APPS-4301", "APPS-4302", "APPS-4303", "APPS-4304", "NETW-3301", "NETW-3302"),
            specs.map { it.id },
        )
        assertEquals(setOf(Tier.ROOT), specs.map { it.requiredTier }.toSet())
    }

    @Test
    fun `trusted computers are listed with the fingerprint adb shows`() = runTest {
        // "AAAA" decodes to three zero bytes.
        val root = FakeRoot(keys = v("AAAA alexandros@manjaro\nAAAA\n"))
        val outcome = TrustedComputersCheck(root).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 computers are trusted for USB debugging: alexandros@manjaro and a computer without a name", outcome.summary)
        assertEquals("fingerprint 69:3E:9A:F8:4D:3D:FC:C7:1E:64:0E:00:5B:DC:5E:2E", outcome.evidence[1].note)

        assertEquals(Status.PASS, TrustedComputersCheck(FakeRoot(keys = v(null))).run(context).status)
        assertEquals(Status.PASS, TrustedComputersCheck(FakeRoot(keys = v("\n"))).run(context).status)
        assertEquals(Status.UNKNOWN, TrustedComputersCheck(FakeRoot(keys = Reading.Unavailable("denied", source))).run(context).status)
    }

    @Test
    fun `root modules are listed, and only enabled ones count`() = runTest {
        val listing = """
            @@module zygisk_next
            id=zygisk_next
            name=Zygisk Next
            version=1.2
            author=Dr-TSNG
            @@module old_one
            @@disabled
            name=Old module
            @@module going
            @@remove
            name=Going away
        """.trimIndent()
        val modules = assertIs<RootModules.Result.Parsed>(RootModules.parse(listing)).modules
        assertEquals(listOf(true, false, true), modules.map { it.enabled })
        assertEquals("Dr-TSNG", modules[0].author)
        assertTrue(modules[2].removing)

        val outcome = RootModulesCheck(FakeRoot(modules = v(listing))).run(context)
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 root modules enabled: Zygisk Next and Going away", outcome.summary)
        assertEquals(Status.PASS, RootModulesCheck(FakeRoot(modules = v(""))).run(context).status)
        assertEquals(Status.UNKNOWN, RootModulesCheck(FakeRoot(modules = v("name=stray"))).run(context).status)
    }

    @Test
    fun `Magisk switches are informational even without an installed module`() = runTest {
        val root = FakeRoot(settings = v("key=zygisk|value=1\nkey=denylist|value=0"))
        val check = RootModulesCheck(root)
        val result = check.run(context)
        assertEquals(Status.PASS, result.status)
        assertEquals("on", result.evidence.single { it.label == "Zygisk" }.value)
        assertEquals("off", result.evidence.single { it.label == "Enforce DenyList" }.value)
        root.modules = Reading.Unavailable("permission denied", source)
        val unreadModules = check.run(context)
        assertEquals(Status.UNKNOWN, unreadModules.status)
        assertEquals("on", unreadModules.evidence.single { it.label == "Zygisk" }.value)
        root.settings = v("")
        assertEquals("Magisk default", check.run(context).evidence.single { it.label == "Zygisk" }.note)
        root.settings = Reading.Unavailable("refused", source)
        assertNull(check.run(context).evidence.single { it.label == "Zygisk" }.value)
        root.manager = v(RootManager.KERNELSU)
        assertTrue(check.run(context).evidence.none { it.label == "Zygisk" })
    }

    @Test
    fun `prompt protections distinguish confirmed off from unreadable`() = runTest {
        val root = FakeRoot(settings = v("key=su_biometric|value=1"))
        val check = MagiskPromptCheck(root, lock())
        assertEquals(Status.PASS, check.run(context).status)
        root.tapjack = Reading.Unsupported("no switch in this release", source)
        assertEquals(Status.UNSUPPORTED, check.run(context).status)
        root.version = v(31100)
        root.tapjack = v(true)
        assertEquals(Status.UNSUPPORTED, check.run(context).status)
        root.version = v(30700)
        root.tapjack = v(false)
        assertEquals(Status.FAIL, check.run(context).status)
        root.tapjack = Reading.Unavailable("unsupported preference", source)
        assertEquals(Status.UNKNOWN, check.run(context).status)
        root.settings = v("")
        assertEquals(Status.FAIL, check.run(context).status)
        root.settings = v("key=su_biometric|value=1\nunexpected row")
        assertEquals(Status.UNKNOWN, check.run(context).status)
        root.settings = v("key=su_biometric|value=1")
        assertEquals(Status.FAIL, MagiskPromptCheck(root, lock(false)).run(context).status)
        assertEquals(Status.UNSUPPORTED, check.run(context.copy(appUid = 1010132)).status)
        root.manager = v(RootManager.APATCH)
        assertEquals(Status.UNSUPPORTED, check.run(context).status)
    }

    @Test
    fun `LSPosed policy and configured scope are independent observations`() = runTest {
        val root = FakeRoot()
        val check = LSPosedCheck(root, packages)
        assertEquals(Status.UNSUPPORTED, check.run(context).status)
        val rows = "module\torg.example.mod\tsystem\nmodule\torg.example.mod\tcom.termux\nmodule\torg.example.no_scope\t"
        root.lsp = v("policy=denied\n$rows\nend")
        val partial = check.run(context)
        assertEquals(Status.FAIL, partial.status)
        assertEquals(io.github.capitan0n.droynis.core.Severity.INFO, check.spec.severity)
        assertTrue(partial.summary.contains("2 enabled LSPosed modules"))
        assertEquals("Selected: System Framework (system), Termux (com.termux)",
            partial.evidence.single { it.packageName == "org.example.mod" }.note)
        assertEquals("no targets selected for this profile", partial.evidence.last().note)
        root.lsp = v("policy=allowed\n$rows\nend")
        assertEquals(Status.PASS, check.run(context).status)
        root.lsp = v("policy=unknown\nend")
        assertEquals(Status.UNKNOWN, check.run(context).status)
        root.lsp = v("policy=denied\ninventory=unknown\nend")
        assertTrue(check.run(context).summary.contains("policy test failed"))
        for (raw in listOf("policy=allowed\ninventory=unknown\nend", "policy=allowed\n$rows",
                "policy=allowed\nmodule\tbad/package\tsystem\nend", "unrecognized installation")) {
            root.lsp = v(raw)
            assertEquals(Status.UNKNOWN, check.run(context).status)
        }
    }

    @Test
    fun `apps allowed root in Magisk fail, except Droynis itself`() = runTest {
        val table = "uid=10130|policy=2|until=0\nuid=10131|policy=1|until=0\nuid=2000|policy=2|until=0\n" +
            "uid=10132|policy=2|until=0\nuid=10133|policy=2|until=1000\n"
        val outcome = RootAppsCheck(FakeRoot(policies = v(table)), packages).run(context)

        assertEquals(Status.FAIL, outcome.status)
        // 10131 is denied, 10133's grant expired in 1970, 10132 is Droynis.
        // adb's shell is named, but it is no app.
        assertEquals("adb shell and 1 app can get root: Termux", outcome.summary)
        assertTrue(outcome.evidence.any { it.value == "Droynis" && it.note!!.startsWith("this app") })

        val shellOnly = RootAppsCheck(FakeRoot(policies = v("uid=2000|policy=2|until=0")), packages).run(context)
        assertEquals("adb shell can get root", shellOnly.summary)
    }

    @Test
    fun `a Magisk app hidden under another name is pointed out`() = runTest {
        assertEquals("org.kde.kdeconnect_tp", MagiskStrings.hiddenManager("key=requester|value=org.kde.kdeconnect_tp\n"))
        assertNull(MagiskStrings.hiddenManager(""))
        assertNull(MagiskStrings.hiddenManager("key=other|value=x\nrequester"))

        val table = v("uid=10130|policy=2|until=0")
        val hidden = RootAppsCheck(FakeRoot(policies = table, strings = v("key=requester|value=org.kde.kdeconnect_tp")), packages).run(context)
        val row = hidden.evidence.single { it.label == "Magisk app" }
        assertEquals("KDE Connect (org.kde.kdeconnect_tp)", row.value)
        assertEquals("org.kde.kdeconnect_tp", row.packageName)

        // Not hidden, a package that isn't installed, or a table that can't be read: nothing is added, nothing breaks.
        for (strings in listOf(v(""), v("key=requester|value=gone.app"), Reading.Unavailable("no such table", source))) {
            val outcome = RootAppsCheck(FakeRoot(policies = table, strings = strings), packages).run(context)
            assertEquals(Status.FAIL, outcome.status)
            assertTrue(outcome.evidence.none { it.label == "Magisk app" })
        }
    }

    @Test
    fun `an app id matches the app in every user`() = runTest {
        val outcome = RootAppsCheck(FakeRoot(policies = v("uid=1010130|policy=2|until=0")), packages).run(context)
        assertEquals("1 app can get root: uid 1010130", outcome.summary) // another user's copy, not in this user's list

        val ownerManaged = RootAppsCheck(FakeRoot(policies = v("uid=10130|policy=3|until=0")), packages).run(context)
        assertEquals("1 app can get root: Termux", ownerManaged.summary)
        assertEquals("restricted root", ownerManaged.evidence.last().note)
    }

    @Test
    fun `only Droynis or nobody with root passes`() = runTest {
        assertEquals(Status.PASS, RootAppsCheck(FakeRoot(policies = v("")), packages).run(context).status)
        assertEquals(Status.PASS, RootAppsCheck(FakeRoot(policies = v("uid=10132|policy=2|until=0")), packages).run(context).status)
    }

    @Test
    fun `other root managers are not applicable, odd output is unknown`() = runTest {
        val kernelSu = RootAppsCheck(FakeRoot(manager = v(RootManager.KERNELSU)), packages).run(context)
        assertEquals(Status.UNSUPPORTED, kernelSu.status)
        assertEquals(Status.UNKNOWN, RootAppsCheck(FakeRoot(policies = v("uid=1|policy=2")), packages).run(context).status)
        assertNull(MagiskPolicies.parse("uid=10130|policy=2|until=0|logging=1"))
    }

    @Test
    fun `a boot script a non-root user can change fails`() = runTest {
        val listing = "D 700 root /data/adb\n" +
            "D 755 root /data/adb/service.d\n" +
            "F 777 shell /data/adb/service.d/evil.sh\n"
        val outcome = BootScriptsCheck(FakeRoot(bootScripts = v(listing))).run(context)
        assertEquals(Status.FAIL, outcome.status)
        assertTrue(outcome.summary.contains("evil.sh"), outcome.summary)

        // Safe file, but its folder is world-writable: still exposed.
        val badDir = "D 777 shell /data/adb/service.d\nF 700 root /data/adb/service.d/ok.sh\n"
        assertEquals(Status.FAIL, BootScriptsCheck(FakeRoot(bootScripts = v(badDir))).run(context).status)
    }

    @Test
    fun `root-owned boot scripts and an empty set pass, odd output is unknown`() = runTest {
        val safe = "D 700 root /data/adb\nF 700 root /data/adb/service.d/ok.sh\n"
        assertEquals(Status.PASS, BootScriptsCheck(FakeRoot(bootScripts = v(safe))).run(context).status)
        assertEquals(Status.PASS, BootScriptsCheck(FakeRoot(bootScripts = v("D 700 root /data/adb\n"))).run(context).status)
        assertEquals(Status.UNKNOWN, BootScriptsCheck(FakeRoot(bootScripts = v("junk"))).run(context).status)
        assertEquals(Status.UNKNOWN, BootScriptsCheck(FakeRoot(bootScripts = Reading.Unavailable("denied", source))).run(context).status)
    }

    @Test
    fun `scripts and executables staged in temp fail, data files and an empty folder pass`() = runTest {
        val listing = "F 777 shell 987 1759000000 /data/local/tmp/rogue_rndis.sh\n" +
            "F 644 shell 10 1759000000 /data/local/tmp/notes.txt\n"
        val outcome = TempFilesCheck(FakeRoot(tempFiles = v(listing))).run(context)
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 program staged in /data/local/tmp: rogue_rndis.sh, 1 of them world-writable", outcome.summary)
        assertTrue(outcome.evidence.single().note!!.contains("world-writable"))

        val groupOnly = TempFilesCheck(FakeRoot(tempFiles = v("F 770 shell 10 1759000000 /data/local/tmp/group.sh"))).run(context)
        assertNull(groupOnly.evidence.single().note)
        assertTrue("world-writable" !in groupOnly.summary)

        val dataOnly = "F 644 shell 10 1759000000 /data/local/tmp/notes.txt\n"
        assertEquals(Status.PASS, TempFilesCheck(FakeRoot(tempFiles = v(dataOnly))).run(context).status)
        assertEquals(Status.PASS, TempFilesCheck(FakeRoot(tempFiles = v(""))).run(context).status)
        assertEquals(Status.UNKNOWN, TempFilesCheck(FakeRoot(tempFiles = v("garbage"))).run(context).status)
        assertEquals(Status.UNKNOWN, TempFilesCheck(FakeRoot(tempFiles = Reading.Unavailable("denied", source))).run(context).status)
    }

    @Test
    fun `root over adb fails, apps-only passes, and the Magisk default fails`() = runTest {
        suspend fun adb(settings: String) = AdbRootCheck(FakeRoot(settings = v(settings))).run(context)

        assertEquals(Status.FAIL, adb("key=root_access|value=3").status)
        assertEquals(Status.FAIL, adb("key=root_access|value=2").status)
        assertEquals(Status.PASS, adb("key=root_access|value=1").status)
        assertEquals(Status.PASS, adb("key=root_access|value=0").status)

        // Absent root_access means Magisk's default, which is Apps and ADB.
        val default = adb("key=zygisk|value=1")
        assertEquals(Status.FAIL, default.status)
        assertTrue(default.evidence.single().note!!.contains("default"), default.evidence.single().note)
    }

    @Test
    fun `Magisk 31 point 1 reads explicit adb grants and ignores the removed switch`() = runTest {
        val root = FakeRoot(version = v(31100), settings = v("key=root_access|value=3"))
        val check = AdbRootCheck(root)
        assertEquals(Status.PASS, check.run(context).status)
        root.policies = v("uid=2000|policy=2|until=0")
        assertEquals(Status.FAIL, check.run(context).status)
        root.policies = v("uid=2000|policy=2|until=1000\nuid=10130|policy=2|until=0")
        assertEquals(Status.PASS, check.run(context).status)
        root.policies = v("uid=2000|policy=5|until=0")
        assertEquals(Status.UNKNOWN, check.run(context).status)
        root.version = Reading.Unavailable("missing", source)
        assertEquals(Status.UNKNOWN, check.run(context).status)
    }

    @Test
    fun `root over adb is not applicable off Magisk, and unknown when it can't be read`() = runTest {
        assertEquals(Status.UNSUPPORTED, AdbRootCheck(FakeRoot(manager = v(RootManager.KERNELSU))).run(context).status)
        assertEquals(Status.UNKNOWN, AdbRootCheck(FakeRoot(settings = Reading.Unavailable("magisk missing", source))).run(context).status)
        assertEquals(Status.UNKNOWN, AdbRootCheck(FakeRoot(settings = v("garbage output"))).run(context).status)
        assertEquals(emptyMap<String, Int>(), MagiskSettings.parse(""))
        assertNull(MagiskSettings.parse("nonsense"))
    }

    @Test
    fun `listening sockets of user apps fail, loopback and system services do not`() = runTest {
        val tcp = HEADER +
            // 0.0.0.0:8022 LISTEN by Termux
            "   0: 00000000:1F56 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10130        0 1 1 0 100 0 0 10 0\n" +
            // 127.0.0.1:5037 LISTEN by Termux: loopback only
            "   1: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10130        0 2 1 0 100 0 0 10 0\n" +
            // 192.168.1.20:443 ESTABLISHED: a client connection
            "   2: 1401A8C0:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000 10130        0 3 1 0 20 4 30 10 -1\n" +
            // :: listening by system uid 1000
            "   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1 0 100 0 0 10 0\n"
        val tcp6 = HEADER +
            // [::]:1716 LISTEN by KDE Connect
            "   0: 00000000000000000000000000000000:06B4 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10134        0 5 1 0 100 0 0 10 0\n" +
            // [::1]:9000 LISTEN: loopback
            "   1: 00000000000000000000000001000000:2328 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10134        0 6 1 0 100 0 0 10 0\n"
        val udp = HEADER +
            // 0.0.0.0:1716 unconnected, fixed port: KDE Connect discovery
            "  10: 00000000:06B4 00000000:0000 07 00000000:00000000 00:00000000 00000000 10134        0 7 2 0 0\n" +
            // 0.0.0.0:41234 unconnected but ephemeral: a client socket (QUIC, DNS)
            "  11: 00000000:A112 00000000:0000 07 00000000:00000000 00:00000000 00000000 10130        0 8 2 0 0\n"
        val root = FakeRoot(
            net = mapOf(
                ProcNet.TCP to v(tcp),
                ProcNet.TCP6 to v(tcp6),
                ProcNet.UDP to v(udp),
                ProcNet.UDP6 to Reading.Unsupported("no IPv6", source),
            ),
        )
        val outcome = ListeningAppsCheck(root, packages).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(
            "2 apps accept connections from the network: Termux (TCP 8022 on 0.0.0.0) and " +
                "KDE Connect (TCP 1716 on ::, UDP 1716 on 0.0.0.0)",
            outcome.summary,
        )
        assertTrue(outcome.evidence.any { it.label == "System services listening" && it.value == "1" })
    }

    @Test
    fun `no open user ports pass, unreadable or odd tables are unknown`() = runTest {
        assertEquals(Status.PASS, ListeningAppsCheck(FakeRoot(), packages).run(context).status)

        val denied = FakeRoot(net = ProcNet.entries.associateWith { Reading.Unavailable("denied", source) })
        assertEquals(Status.UNKNOWN, ListeningAppsCheck(denied, packages).run(context).status)

        val odd = FakeRoot(net = ProcNet.entries.associateWith { v(HEADER + "garbage line\n") })
        assertEquals(Status.UNKNOWN, ListeningAppsCheck(odd, packages).run(context).status)
    }

    private fun smsPolicy(vararg apps: Pair<String, Int>) = v(
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<premium-sms-policy>\n" +
            apps.joinToString("") { (pkg, policy) -> "<package name=\"$pkg\" sms-policy=\"$policy\" />\n" } +
            "</premium-sms-policy>\n",
    )

    @Test
    fun `apps allowed to text premium numbers fail, others and uninstalled ones don't count`() = runTest {
        val root = FakeRoot(
            premiumSms = smsPolicy("com.termux" to 3, "org.kde.kdeconnect_tp" to 1, "org.example.gone" to 3, "org.example.denied" to 2),
        )
        val outcome = PremiumSmsCheck(root, packages).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 app may text premium numbers without asking: Termux", outcome.summary)
        assertEquals("4", outcome.evidence.single { it.label == "Apps with a premium SMS setting" }.value)
        val allowed = outcome.evidence.filter { it.label == "Always allowed" }
        assertEquals(listOf("Termux (com.termux)", "org.example.gone"), allowed.map { it.value })
        assertEquals("not installed; not counted", allowed.last().note)

        val trusted = PremiumSmsCheck(root, packages).run(context.copy(trustedApps = setOf("com.termux")))
        assertEquals(Status.PASS, trusted.status)
        assertEquals("Only apps you trust may text premium numbers without asking: Termux", trusted.summary)
    }

    @Test
    fun `no file or no app always allowed passes, an odd or unreadable file is unknown`() = runTest {
        val none = PremiumSmsCheck(FakeRoot(), packages).run(context)
        assertEquals(Status.PASS, none.status)
        assertEquals("the file doesn't exist yet", none.evidence.single().note)

        assertEquals(Status.PASS, PremiumSmsCheck(FakeRoot(premiumSms = smsPolicy("com.termux" to 1)), packages).run(context).status)
        assertEquals(Status.UNKNOWN, PremiumSmsCheck(FakeRoot(premiumSms = v("ABX\u0000binary")), packages).run(context).status)
        assertEquals(
            Status.UNKNOWN,
            PremiumSmsCheck(FakeRoot(premiumSms = Reading.Unavailable("permission denied", source)), packages).run(context).status,
        )
    }

    @Test
    fun `the premium SMS file parser never skips a package it can't read`() {
        assertEquals(
            mapOf("a.b" to 3, "c.d" to 2),
            PremiumSmsPolicies.parse("<premium-sms-policy><package sms-policy=\"3\" name=\"a.b\"/><package name=\"c.d\" sms-policy=\"2\"></package></premium-sms-policy>"),
        )
        assertEquals(emptyMap(), PremiumSmsPolicies.parse("<premium-sms-policy />"))
        assertNull(PremiumSmsPolicies.parse("<premium-sms-policy><package name=\"a.b\" /></premium-sms-policy>"))
        assertNull(PremiumSmsPolicies.parse("<premium-sms-policy><package name=\"a.b\" sms-policy=\"always\" /></premium-sms-policy>"))
        assertNull(PremiumSmsPolicies.parse("<package name=\"a.b\" sms-policy=\"3\" />"))
    }

    @Test
    fun `addresses decode from the kernel's byte order`() {
        val ports = ProcNetSockets.parse(
            HEADER + "   0: 1401A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10130 0 1 1\n" +
                "   1: 0000000000000000FFFF00000100007F:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10130 0 1 1\n" +
                "   2: 0000000000000000FFFF00001401A8C0:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10130 0 1 1\n",
            ProcNet.TCP,
        )!!
        // ::ffff:127.0.0.1 is loopback and dropped.
        assertEquals(listOf("192.168.1.20" to 8080, "::ffff:192.168.1.20" to 8082), ports.map { it.address to it.port })
    }

    private companion object {
        const val HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

        val APPS = listOf(
            InstalledApp("com.termux", isSystem = false, isDebuggable = false, installer = null, targetSdk = 28, uid = 10130),
            InstalledApp("org.example.denied", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35, uid = 10131),
            InstalledApp("org.kde.kdeconnect_tp", isSystem = false, isDebuggable = false, installer = null, targetSdk = 35, uid = 10134),
        )
        val LABELS = mapOf("com.termux" to "Termux", "org.kde.kdeconnect_tp" to "KDE Connect")
    }
}
