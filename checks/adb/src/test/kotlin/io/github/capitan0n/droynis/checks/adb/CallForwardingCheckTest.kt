package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.CellularProbe
import io.github.capitan0n.droynis.checks.base.CellularSecurity
import io.github.capitan0n.droynis.checks.base.SimCard
import io.github.capitan0n.droynis.checks.base.SimTelephony
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.SettingsActions
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

/** `dumpsys telephony.registry` (TelephonyRegistryDump) and call forwarding (NETW-3106). */
class CallForwardingCheckTest {

    private val source = Source("dumpsys telephony.registry", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 11, 12, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 36)

    private class FakeCellular(private val sims: Reading<List<SimCard>>) : CellularProbe {
        override fun sims() = sims
        override fun twoGDisallowed(): Reading<Boolean> = Reading.Unsupported("unused", Source("fake"))
        override fun privileged(): Reading<List<SimTelephony>> = Reading.Unsupported("unused", Source("fake"))
        override fun security(): Reading<CellularSecurity> = Reading.Unsupported("unused", Source("fake"))
    }

    private fun sims(vararg slots: Int?): Reading<List<SimCard>> =
        Reading.Value(slots.mapIndexed { i, slot -> SimCard(slot, subId = i + 1) }, Source("fake"))

    private fun check(text: String?, sims: Reading<List<SimCard>> = sims(0)) = CallForwardingCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String): Reading<String> {
                assertEquals("telephony.registry", service)
                return if (text == null) Reading.Unavailable("Permission Denial", source) else Reading.Value(text, source)
            }
        },
        FakeCellular(sims),
    )

    /** The shape of TelephonyRegistry's dump on Android 12 to 16, with a caller's number that must never surface. */
    private fun registry(vararg forwarding: Boolean) = buildString {
        appendLine("last known state:")
        forwarding.forEachIndexed { id, on ->
            appendLine("  Phone Id=$id")
            appendLine("    mCallState=0")
            appendLine("    mCallIncomingNumber=+15551234567")
            appendLine("    mMessageWaiting=false")
            appendLine("    mCallForwarding=$on")
            appendLine("    mDataActivity=0")
        }
        appendLine("local logs:")
        appendLine("  notifyCallForwardingChangedForSubscriber: subId=1 cfi=true")
        appendLine("registrations: count=3")
    }

    @Test
    fun `needs dump only and opens the call settings`() {
        val spec = check("").spec
        assertEquals("NETW-3106", spec.id)
        assertEquals(setOf(Grant.DUMP), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(listOf(SettingsActions.CALL_SETTINGS), spec.remediation.settingsActions)
    }

    @Test
    fun `the parser reads each phone's state and ignores the logs`() {
        val parsed = TelephonyRegistryDump.parse(registry(false, true))
        assertIs<TelephonyRegistryDump.Result.Parsed>(parsed)
        assertEquals(mapOf(0 to false, 1 to true), parsed.callForwarding)

        // Older single-SIM releases print no phone id.
        val single = TelephonyRegistryDump.parse("last known state:\n  mCallForwarding=false\n")
        assertEquals(TelephonyRegistryDump.Result.Parsed(mapOf(0 to false)), single)
    }

    @Test
    fun `anything unexpected is a failure to parse, never a value`() {
        assertIs<TelephonyRegistryDump.Result.Failed>(TelephonyRegistryDump.parse("last known state:\n  Phone Id=0\n    mCallState=0\n"))
        assertIs<TelephonyRegistryDump.Result.Failed>(TelephonyRegistryDump.parse("  Phone Id=0\n    mCallForwarding=maybe\n"))
        assertIs<TelephonyRegistryDump.Result.Failed>(
            TelephonyRegistryDump.parse("  Phone Id=0\n    mCallForwarding=true\n  Phone Id=0\n    mCallForwarding=false\n"),
        )
    }

    @Test
    fun `a SIM that forwards all calls fails, and no number is kept`() = runTest {
        val outcome = check(registry(false, true), sims(0, 1)).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("SIM 2 forwards all calls to another number", outcome.summary)
        assertEquals(listOf("doesn't forward all calls", "forwards all calls"), outcome.evidence.map { it.value })
        assertFalse(outcome.evidence.any { "555" in it.value.orEmpty() || "555" in it.note.orEmpty() })
    }

    @Test
    fun `only SIMs in use count, by slot`() = runTest {
        // The second slot is empty: its state is not judged.
        val outcome = check(registry(false, true), sims(0)).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("SIM 1 doesn't forward all calls", outcome.summary)
        assertEquals(listOf("Call forwarding, SIM 1"), outcome.evidence.map { it.label })
    }

    @Test
    fun `without slots every listed slot is judged`() = runTest {
        val outcome = check(registry(false, false), sims(null)).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("No SIM in use forwards all calls", outcome.summary)
        assertEquals(listOf("Call forwarding, SIM slot 1", "Call forwarding, SIM slot 2"), outcome.evidence.map { it.label })
    }

    @Test
    fun `a SIM missing from the registry, or a registry that can't be read, is unknown`() = runTest {
        val missing = check(registry(false), sims(0, 1)).run(context)
        assertEquals(Status.UNKNOWN, missing.status)
        assertEquals("Call forwarding could not be read for SIM 2", missing.summary)

        assertEquals(Status.UNKNOWN, check(null).run(context).status)
        assertEquals(Status.UNKNOWN, check("Can't parse this").run(context).status)
    }

    @Test
    fun `no SIM or no mobile network is not applicable`() = runTest {
        assertEquals(Status.UNSUPPORTED, check(registry(false), sims()).run(context).status)
        val noRadio = check(registry(false), Reading.Unsupported("no telephony", Source("fake"))).run(context)
        assertEquals(Status.UNSUPPORTED, noRadio.status)
        assertTrue(noRadio.summary.contains("no mobile network"))
    }
}
