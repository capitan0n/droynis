package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.InstalledApp
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
        var net: Map<ProcNet, Reading<String>> = ProcNet.entries.associateWith { Reading.Value(HEADER, Source("su")) },
    ) : RootShellProbe {
        override fun adbKeys() = keys
        override fun modules() = modules
        override fun manager() = manager
        override fun magiskPolicies() = policies
        override fun procNet(table: ProcNet) = net.getValue(table)
    }

    private val packages = object : PackageInventory {
        override fun installedApps(): Reading<List<InstalledApp>> = Reading.Value(APPS, Source("fake"))
        override fun label(packageName: String) = LABELS[packageName] ?: packageName
    }

    @Test
    fun `every root check needs the root tier`() {
        val specs = rootChecks(
            object : RootProbes {
                override val root = FakeRoot()
                override val packages = this@RootChecksTest.packages
            },
        ).map { it.spec }

        assertEquals(listOf("INTG-1301", "ACCS-2301", "APPS-4301", "NETW-3301"), specs.map { it.id })
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
        assertEquals("2 root modules active: Zygisk Next and Going away", outcome.summary)
        assertEquals(Status.PASS, RootModulesCheck(FakeRoot(modules = v(""))).run(context).status)
        assertEquals(Status.UNKNOWN, RootModulesCheck(FakeRoot(modules = v("name=stray"))).run(context).status)
    }

    @Test
    fun `apps allowed root in Magisk fail, except Droynis itself`() = runTest {
        val table = "uid=10130|policy=2|until=0\nuid=10131|policy=1|until=0\nuid=2000|policy=2|until=0\n" +
            "uid=10132|policy=2|until=0\nuid=10133|policy=2|until=1000\n"
        val outcome = RootAppsCheck(FakeRoot(policies = v(table)), packages).run(context)

        assertEquals(Status.FAIL, outcome.status)
        // 10131 is denied, 10133's grant expired in 1970, 10132 is Droynis.
        assertEquals("2 apps can get root: Termux and adb shell", outcome.summary)
        assertTrue(outcome.evidence.any { it.value == "Droynis" && it.note!!.startsWith("this app") })
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
