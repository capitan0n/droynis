package io.github.capitan0n.droynis.checks.shizuku

import io.github.capitan0n.droynis.checks.base.CellularProbe
import io.github.capitan0n.droynis.checks.base.CellularSecurity
import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.PrivilegedSwitch
import io.github.capitan0n.droynis.checks.base.SimCard
import io.github.capitan0n.droynis.checks.base.SimTelephony
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class ShizukuChecksTest {

    private val shellSource = Source("settings get secure", Grant.SHIZUKU)
    private val context = ScanContext(ZonedDateTime.of(2026, 10, 5, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun value(raw: String?): Reading<String?> = Reading.Value(raw, shellSource)

    private val inventory = object : PackageInventory {
        override fun installedApps(): Reading<List<InstalledApp>> = Reading.Value(emptyList(), shellSource)
        override fun label(packageName: String) = if (packageName == "org.example.vpn") "Example VPN" else packageName
    }

    private fun shell(reading: Reading<String>) = object : PrivilegedShell {
        override fun selinuxMode() = reading
    }

    private fun settings(app: Reading<String?>, lockdown: Reading<String?>) = object : SystemSettings {
        override fun global(key: String) = value(null)
        override fun secure(key: String) = when (key) {
            AlwaysOnVpnCheck.ALWAYS_ON_VPN_APP -> app
            AlwaysOnVpnCheck.ALWAYS_ON_VPN_LOCKDOWN -> lockdown
            else -> value(null)
        }
        override fun system(key: String) = value(null)
    }

    private fun selinux(reading: Reading<String>) = SelinuxCheck(shell(reading))

    private fun vpn(app: Reading<String?>, lockdown: Reading<String?> = value(null)) =
        AlwaysOnVpnCheck(settings(app, lockdown), inventory)

    private fun cellular(
        sims: Reading<List<SimCard>> = Reading.Value(listOf(SimCard(0, 1)), shellSource),
        privileged: Reading<List<SimTelephony>> = Reading.Value(emptyList(), shellSource),
        security: Reading<CellularSecurity> = Reading.Unavailable("neither Shizuku nor root is connected", shellSource),
    ) = object : CellularProbe {
        override fun sims() = sims
        override fun twoGDisallowed() = Reading.Unsupported("needs Android 14", shellSource)
        override fun privileged() = privileged
        override fun security() = security
    }

    private val unsupported = PrivilegedSwitch(null, "UnsupportedOperationException")

    private fun security(
        nullCipherAllowed: PrivilegedSwitch = PrivilegedSwitch(true),
        nullCipherAlerts: PrivilegedSwitch = PrivilegedSwitch(false),
        identifierAlerts: PrivilegedSwitch = PrivilegedSwitch(false),
    ) = cellular(security = Reading.Value(CellularSecurity(nullCipherAllowed, nullCipherAlerts, identifierAlerts), shellSource))

    private suspend fun simPin(vararg sims: SimTelephony, inUse: List<SimCard> = listOf(SimCard(0, 1))) =
        SimPinCheck(cellular(Reading.Value(inUse, shellSource), Reading.Value(sims.toList(), shellSource))).run(context)

    @Test
    fun `every check needs the Shizuku tier`() {
        val probes = object : ShizukuProbes {
            override val settings = settings(value(null), value(null))
            override val packages = inventory
            override val shell = shell(Reading.Value("Enforcing", shellSource))
            override val cellular = cellular(privileged = Reading.Value(emptyList(), shellSource))
        }
        val specs = shizukuChecks(probes).map { it.spec }

        assertEquals(listOf("INTG-1201", "ACCS-2201", "NETW-3201", "NETW-3202", "NETW-3203"), specs.map { it.id })
        assertEquals(setOf(Tier.SHIZUKU), specs.map { it.requiredTier }.toSet())
    }

    @Test
    fun `selinux enforcing passes, anything weaker fails critically`() = runTest {
        assertEquals(Status.PASS, selinux(Reading.Value("Enforcing\n", shellSource)).run(context).status)

        val permissive = selinux(Reading.Value("Permissive", shellSource))
        assertEquals(Status.FAIL, permissive.run(context).status)
        assertEquals(Severity.CRITICAL, permissive.spec.severity)
        assertEquals(Status.FAIL, selinux(Reading.Value("Disabled", shellSource)).run(context).status)
    }

    @Test
    fun `an error or an unknown selinux answer is unknown, never a pass`() = runTest {
        val denied = "getenforce: Couldn't get enforcing status: Permission denied"
        assertEquals(Status.UNKNOWN, selinux(Reading.Value(denied, shellSource)).run(context).status)
        assertEquals(Status.UNKNOWN, selinux(Reading.Unavailable("Shizuku stopped", shellSource)).run(context).status)
    }

    @Test
    fun `always-on vpn with lockdown passes`() = runTest {
        val outcome = vpn(value("org.example.vpn"), value("1")).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("Example VPN is always on and blocks connections without the VPN", outcome.summary)
        assertEquals("Example VPN (org.example.vpn)", outcome.evidence.first().value)
    }

    @Test
    fun `always-on vpn without lockdown fails`() = runTest {
        assertEquals(Status.FAIL, vpn(value("org.example.vpn"), value("0")).run(context).status)
        assertEquals(Status.FAIL, vpn(value("org.example.vpn"), value(null)).run(context).status)
        assertEquals(Status.UNKNOWN, vpn(value("org.example.vpn"), value("yes")).run(context).status)
    }

    @Test
    fun `no always-on vpn is not applicable, and an unreadable one is unknown`() = runTest {
        assertEquals(Status.UNSUPPORTED, vpn(value(null)).run(context).status)
        assertEquals(Status.UNSUPPORTED, vpn(value("")).run(context).status)
        assertEquals(Status.UNKNOWN, vpn(Reading.Unavailable("access denied", shellSource)).run(context).status)
    }

    @Test
    fun `a SIM without its PIN fails, every SIM locked passes`() = runTest {
        assertEquals(Status.PASS, simPin(SimTelephony(1, 0, pinLocked = true)).status)

        val open = simPin(SimTelephony(1, 0, pinLocked = false))
        assertEquals(Status.FAIL, open.status)
        assertEquals("SIM 1 has no PIN: taken out, it works in any other phone", open.summary)
        assertEquals("off", open.evidence.single { it.label == "SIM 1 PIN" }.value)

        val dual = simPin(
            SimTelephony(1, 0, pinLocked = true),
            SimTelephony(2, 1, pinLocked = false),
            inUse = listOf(SimCard(0, 1), SimCard(1, 2)),
        )
        assertEquals("SIM 2 has no PIN: taken out, it works in any other phone", dual.summary)
    }

    @Test
    fun `the SIM PIN check never passes on what it could not read`() = runTest {
        assertEquals(Status.UNKNOWN, simPin(SimTelephony(1, 0, pinLocked = null)).status)
        assertEquals(Status.UNKNOWN, simPin().status)
        // An inactive subscription the shell also lists does not count.
        assertEquals(Status.UNKNOWN, simPin(SimTelephony(9, null, pinLocked = true)).status)
        val unreadable = SimPinCheck(cellular(privileged = Reading.Unavailable("Shizuku stopped", shellSource))).run(context)
        assertEquals(Status.UNKNOWN, unreadable.status)

        val noSim = SimPinCheck(
            cellular(Reading.Value(emptyList(), shellSource), Reading.Value(emptyList(), shellSource)),
        ).run(context)
        assertEquals(Status.UNSUPPORTED, noSim.status)
        val noRadio = SimPinCheck(
            cellular(Reading.Unsupported("no telephony", shellSource), Reading.Value(emptyList(), shellSource)),
        ).run(context)
        assertEquals(Status.UNSUPPORTED, noRadio.status)
    }

    @Test
    fun `accepting connections without encryption fails, requiring encryption passes`() = runTest {
        val allowed = CellularEncryptionCheck(security(nullCipherAllowed = PrivilegedSwitch(true))).run(context)
        assertEquals(Status.FAIL, allowed.status)
        assertEquals("The phone accepts mobile connections without encryption: Require encryption is off", allowed.summary)
        // Evidence shows the switch the way Settings names it.
        assertEquals("off", allowed.evidence.single { it.label == "Require encryption" }.value)
        assertEquals(Grant.SHIZUKU, allowed.evidence.single().source.grant)

        val required = CellularEncryptionCheck(security(nullCipherAllowed = PrivilegedSwitch(false))).run(context)
        assertEquals(Status.PASS, required.status)
        assertEquals("on", required.evidence.single().value)
    }

    @Test
    fun `a modem without the encryption switch is not applicable, an unread one unknown`() = runTest {
        assertEquals(Status.UNSUPPORTED, CellularEncryptionCheck(security(nullCipherAllowed = unsupported)).run(context).status)
        assertEquals(
            Status.UNKNOWN,
            CellularEncryptionCheck(security(nullCipherAllowed = PrivilegedSwitch(null, "SecurityException"))).run(context).status,
        )
        assertEquals(Status.UNKNOWN, CellularEncryptionCheck(cellular()).run(context).status)
        val noRadio = cellular(sims = Reading.Unsupported("no mobile network hardware", shellSource))
        assertEquals(Status.UNSUPPORTED, CellularEncryptionCheck(noRadio).run(context).status)
    }

    @Test
    fun `fake cell tower alerts fail when off and pass when every supported one is on`() = runTest {
        val off = CellularAlertsCheck(security(nullCipherAlerts = PrivilegedSwitch(false), identifierAlerts = PrivilegedSwitch(true))).run(context)
        assertEquals(Status.FAIL, off.status)
        assertEquals("The phone doesn't warn about connections without encryption, signs of a fake cell tower", off.summary)

        val on = CellularAlertsCheck(security(nullCipherAlerts = PrivilegedSwitch(true), identifierAlerts = PrivilegedSwitch(true))).run(context)
        assertEquals(Status.PASS, on.status)

        // A modem with only one of the two alerts is judged on that one.
        val partial = CellularAlertsCheck(security(nullCipherAlerts = unsupported, identifierAlerts = PrivilegedSwitch(true))).run(context)
        assertEquals(Status.PASS, partial.status)
        assertEquals(
            Status.UNSUPPORTED,
            CellularAlertsCheck(security(nullCipherAlerts = unsupported, identifierAlerts = unsupported)).run(context).status,
        )
        assertEquals(
            Status.UNKNOWN,
            CellularAlertsCheck(security(nullCipherAlerts = PrivilegedSwitch(true), identifierAlerts = PrivilegedSwitch(null, "SecurityException")))
                .run(context).status,
        )
    }
}
