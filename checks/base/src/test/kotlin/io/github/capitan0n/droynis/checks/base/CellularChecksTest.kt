package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class CellularChecksTest {

    private val sim1 = SimCard(slot = 0, subId = 1)
    private val sim2 = SimCard(slot = 1, subId = 2)

    /** Everything allowed except 2G, as the Allow 2G switch leaves it when turned off. */
    private val no2g = 0xFFFFFL and NetworkTypes.TWO_G.inv()
    private val all = 0xFFFFFL

    private suspend fun twoG(
        sdk: Int,
        cellular: CellularProbe = FakeCellular(),
        global: Map<String, Reading<String?>> = emptyMap(),
        props: SystemProperties = FakeProperties(),
    ) = Cellular2gCheck(cellular, FakeSettings(global = global), props).run(scanContext(sdk = sdk))

    @Test
    fun `android 11 reads the network mode of each SIM, the way the user's Samsung stores it`() = runTest {
        // From a Galaxy A20e on Android 11: preferred_network_mode1=9, preferred_network_mode=9,9.
        val fail = twoG(30, global = mapOf("preferred_network_mode1" to value("9")))
        assertEquals(Status.FAIL, fail.status)
        assertEquals("The network mode of SIM 1 includes 2G, so the phone may connect to 2G networks", fail.summary)
        assertEquals("LTE/3G/2G (auto)", fail.evidence.single { it.label == "SIM 1 network mode" }.value)

        val pass = twoG(30, global = mapOf("preferred_network_mode1" to value("12")))
        assertEquals(Status.PASS, pass.status)

        // Two SIMs: one with 2G is enough to fail.
        val dual = FakeCellular(sims = value(listOf(sim1, sim2)))
        val mixed = twoG(30, dual, mapOf("preferred_network_mode1" to value("11"), "preferred_network_mode2" to value("26")))
        assertEquals(Status.FAIL, mixed.status)
        assertTrue(mixed.summary.startsWith("The network mode of SIM 2 includes 2G"))
    }

    @Test
    fun `an unset mode falls back to the phone's default, and anything unreadable is unknown`() = runTest {
        val default = FakeProperties(Cellular2gCheck.DEFAULT_NETWORK to "26,26")
        assertEquals(Status.FAIL, twoG(29, props = default).status)
        assertEquals(Status.PASS, twoG(29, props = FakeProperties(Cellular2gCheck.DEFAULT_NETWORK to "24")).status)

        assertEquals(Status.UNKNOWN, twoG(30).status) // unset, default not readable
        assertEquals(Status.UNKNOWN, twoG(30, global = mapOf("preferred_network_mode1" to unavailable("denied"))).status)
        // A vendor's own mode number is never read as "no 2G".
        assertEquals(Status.UNKNOWN, twoG(30, global = mapOf("preferred_network_mode1" to value("99"))).status)
    }

    @Test
    fun `no mobile network or no SIM is not applicable`() = runTest {
        assertEquals(Status.UNSUPPORTED, twoG(30, FakeCellular(sims = unsupported("no telephony"))).status)
        assertEquals(Status.UNSUPPORTED, twoG(36, FakeCellular(sims = value(emptyList()))).status)
    }

    @Test
    fun `android 12 and later need the privileged read, unless policy turned 2G off`() = runTest {
        val unprivileged = twoG(36)
        assertEquals(Status.UNKNOWN, unprivileged.status)
        assertTrue("Shizuku or root" in unprivileged.summary)

        // A readable but stale network mode setting is never trusted on Android 12+.
        assertEquals(Status.UNKNOWN, twoG(36, global = mapOf("preferred_network_mode1" to value("11"))).status)

        val policy = twoG(36, FakeCellular(policy = value(true)))
        assertEquals(Status.PASS, policy.status)
        assertTrue("device policy" in policy.summary)
    }

    @Test
    fun `the Allow 2G switch or a network mode without 2G passes, both allowing 2G fails`() = runTest {
        fun read(vararg reasons: Pair<Int, Long>, sub: Int = 1, slot: Int? = 0) =
            SimTelephony(sub, slot, pinLocked = true, allowedNetworkTypes = mapOf(*reasons))

        val switchOn = twoG(36, FakeCellular(privileged = value(listOf(read(0 to all, 3 to all)))))
        assertEquals(Status.FAIL, switchOn.status)
        assertEquals("SIM 1 may connect to 2G networks: Allow 2G is on", switchOn.summary)
        assertEquals("on", switchOn.evidence.single { it.label == "SIM 1 · Allow 2G switch" }.value)

        val switchOff = twoG(36, FakeCellular(privileged = value(listOf(read(0 to all, 3 to no2g)))))
        assertEquals(Status.PASS, switchOff.status)

        val modeWithout2g = twoG(36, FakeCellular(privileged = value(listOf(read(0 to no2g, 3 to all)))))
        assertEquals(Status.PASS, modeWithout2g.status)

        // Only SIMs in use count: an inactive second subscription is ignored.
        val other = read(0 to all, 3 to all, sub = 7, slot = 1)
        assertEquals(Status.PASS, twoG(36, FakeCellular(privileged = value(listOf(read(3 to no2g), other)))).status)

        assertEquals(Status.UNKNOWN, twoG(36, FakeCellular(privileged = value(listOf(read())))).status)
        assertEquals(Status.UNKNOWN, twoG(36, FakeCellular(privileged = value(emptyList()))).status)
    }

    @Test
    fun `network mode table`() {
        assertEquals(true, NetworkModes.of(9)?.allows2g)
        assertEquals(false, NetworkModes.of(11)?.allows2g)
        assertEquals(false, NetworkModes.of(12)?.allows2g)
        assertEquals(true, NetworkModes.of(26)?.allows2g)
        assertEquals(false, NetworkModes.of(28)?.allows2g)
        // CDMA 1x counts as 2G, as in Android's own NETWORK_CLASS_BITMASK_2G.
        assertEquals(true, NetworkModes.of(8)?.allows2g)
        assertEquals(false, NetworkModes.of(6)?.allows2g)
        assertNull(NetworkModes.of(34))
        assertEquals(32843L, NetworkTypes.TWO_G)
    }

    @Test
    fun `the privileged read's output is parsed strictly`() {
        val text = """
            WARNING: linker: something unrelated
            ${TelephonyDump.HEADER}
            sub=1 slot=0 pin=true reason0=1048575 reason3=1015732
            sub=2 slot=-1 pin=? reason0=x
        """.trimIndent()
        val parsed = assertIs<TelephonyDump.Result.Parsed>(TelephonyDump.parse(text))
        assertEquals(
            listOf(
                SimTelephony(1, 0, true, mapOf(0 to 1048575L, 3 to 1015732L)),
                SimTelephony(2, null, null, emptyMap()),
            ),
            parsed.sims,
        )
        assertEquals(TelephonyDump.Result.Parsed(emptyList()), TelephonyDump.parse(TelephonyDump.HEADER))

        assertIs<TelephonyDump.Result.Failed>(TelephonyDump.parse(""))
        assertIs<TelephonyDump.Result.Failed>(TelephonyDump.parse("Exception in thread main"))
        val failed = assertIs<TelephonyDump.Result.Failed>(TelephonyDump.parse("${TelephonyDump.HEADER}\nerror=no phone service"))
        assertEquals("no phone service", failed.reason)
        assertIs<TelephonyDump.Result.Failed>(TelephonyDump.parse("${TelephonyDump.HEADER}\nsub=x slot=0"))
    }

    @Test
    fun `vendor and kernel patches pass when they keep up with Android's`() = runTest {
        suspend fun check(
            android: String = "2026-09-05",
            vendor: Int? = 20260905,
            boot: Int? = 20260905,
            level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            props: SystemProperties = FakeProperties(VendorPatchCheck.BASEBAND to "A202FXXU3CVA1"),
        ) = VendorPatchCheck(
            FakeBuildInfo(value(android)),
            FakeAttestation(value(KeyAttestation(300, level, null, 202609, vendor, boot))),
            props,
        ).outcome()

        val current = check()
        assertEquals(Status.PASS, current.status)
        assertEquals("A202FXXU3CVA1", current.evidence.single { it.label == "Modem firmware (baseband)" }.value)

        // A custom ROM on 2025 firmware: the kernel is a year and a half behind.
        val rom = check(vendor = 20250301, boot = 202503)
        assertEquals(Status.FAIL, rom.status)
        assertEquals(Severity.CRITICAL, rom.escalation)
        assertTrue(rom.summary.startsWith("The vendor patch (2025-03-01) is over a year behind"))

        val months = check(vendor = 20260905, boot = 20260401)
        assertEquals(Status.FAIL, months.status)
        assertNull(months.escalation)
        assertTrue(months.summary.startsWith("The kernel patch (2026-04-01) is 157 days behind"))

        // An old stock phone is old everywhere: no gap, so this check passes (INTG-1010 fails it).
        assertEquals(Status.PASS, check(android = "2022-03-01", vendor = 20220301, boot = 20220301).status)
    }

    @Test
    fun `without trusted attestation the vendor property is the fallback, never software attestation`() = runTest {
        suspend fun check(attestation: Reading<KeyAttestation>, vararg props: Pair<String, String>) = VendorPatchCheck(
            FakeBuildInfo(value("2026-09-05")),
            FakeAttestation(attestation),
            FakeProperties(*props),
        ).outcome()

        val software = value(KeyAttestation(300, SecurityLevel.SOFTWARE, null, 202609, 20260905, 20260905))
        assertEquals(Status.UNSUPPORTED, check(software).status)
        val fallback = check(software, VendorPatchCheck.VENDOR_PATCH to "2021-01-05")
        assertEquals(Status.FAIL, fallback.status)
        assertEquals(VendorPatchCheck.VENDOR_PATCH, fallback.evidence.single { it.label == "Vendor patch level" }.note)

        val passPropOnly = check(unsupported("no attestation"), VendorPatchCheck.VENDOR_PATCH to "2026-09-01")
        assertEquals(Status.PASS, passPropOnly.status)
        assertTrue("the kernel's isn't reported" in passPropOnly.summary)

        assertEquals(Status.UNKNOWN, check(unavailable("keystore error")).status)
        assertEquals(Status.UNKNOWN, VendorPatchCheck(FakeBuildInfo(unavailable()), FakeAttestation(), FakeProperties()).outcome().status)
    }

    @Test
    fun `patch dates come as YYYYMMDD or YYYYMM`() {
        assertEquals(LocalDate.of(2026, 9, 5), VendorPatchCheck.patchDate(20260905))
        assertEquals(LocalDate.of(2026, 9, 1), VendorPatchCheck.patchDate(202609))
        assertEquals(LocalDate.of(2026, 9, 1), VendorPatchCheck.patchDate(20260900))
        assertNull(VendorPatchCheck.patchDate(0))
        assertNull(VendorPatchCheck.patchDate(20261301))
        assertNull(VendorPatchCheck.patchDate(19700101))
    }

    @Test
    fun `apps that can send SMS, besides the SMS app`() = runTest {
        val apps = FakePackages(
            value(
                listOf(
                    InstalledApp("org.kde.kdeconnect_tp", isSystem = false, isDebuggable = false, installer = "org.fdroid.fdroid", targetSdk = 34),
                    InstalledApp("com.example.flashlight", isSystem = false, isDebuggable = false, installer = null, targetSdk = 30),
                    InstalledApp("com.samsung.android.messaging", isSystem = true, isDebuggable = false, installer = null, targetSdk = 34),
                    InstalledApp("com.android.phone", isSystem = true, isDebuggable = false, installer = null, targetSdk = 34),
                ),
            ),
            labels = mapOf("org.kde.kdeconnect_tp" to "KDE Connect", "com.example.flashlight" to "Flashlight"),
        )
        suspend fun check(holders: Set<String>) = SmsSendingCheck(
            FakePermissions(value(holders.associateWith { SmsSendingCheck.SEND })),
            FakeDefaultApps(sms = value("com.samsung.android.messaging")),
            apps,
        ).outcome()

        assertEquals(Status.PASS, check(setOf("com.samsung.android.messaging", "com.android.phone")).status)
        assertTrue("com.android.phone" !in apps.labelled) // preinstalled: counted, never labelled

        val kde = check(setOf("com.samsung.android.messaging", "org.kde.kdeconnect_tp"))
        assertEquals(Status.FAIL, kde.status)
        assertNull(kde.escalation)

        val sideloaded = check(setOf("com.example.flashlight", "org.kde.kdeconnect_tp"))
        assertEquals(Severity.WARNING, sideloaded.escalation)
        assertEquals(
            "2 apps can send SMS: Flashlight and KDE Connect; Flashlight comes from outside an app store",
            sideloaded.summary,
        )
        assertEquals(
            Status.UNKNOWN,
            SmsSendingCheck(FakePermissions(unavailable()), FakeDefaultApps(), apps).outcome().status,
        )
    }

    @Test
    fun `a proxy on mobile data counts even while Wi-Fi is the default network`() = runTest {
        val mobile = cellular().copy(httpProxy = "10.0.0.5:8080")
        val both = HttpProxyCheck(FakeNetwork(value(wifi()), value(listOf(wifi(), mobile)))).outcome()
        assertEquals(Status.FAIL, both.status)
        assertEquals("Web traffic on mobile data goes through the proxy 10.0.0.5:8080", both.summary)

        val clean = HttpProxyCheck(FakeNetwork(value(wifi()), value(listOf(wifi(), cellular())))).outcome()
        assertEquals(Status.PASS, clean.status)
        assertEquals("No HTTP proxy is set on Wi-Fi and mobile data", clean.summary)

        // Mobile data off: the evidence says it wasn't checked.
        val wifiOnly = HttpProxyCheck(FakeNetwork(value(wifi()))).outcome()
        assertEquals("not connected", wifiOnly.evidence.single { it.label == "Mobile data" }.value)

        // A global proxy shows on the default network only, never on the network itself.
        val global = HttpProxyCheck(FakeNetwork(value(wifi().copy(httpProxy = "proxy.example:3128")), value(listOf(wifi())))).outcome()
        assertEquals("Web traffic on every network (a global proxy) goes through the proxy proxy.example:3128", global.summary)

        assertEquals(Status.UNKNOWN, HttpProxyCheck(FakeNetwork(unavailable())).outcome().status)
    }
}
