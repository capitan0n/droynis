package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.adb.OpenWifiCheckTest.Companion.OPEN
import io.github.capitan0n.droynis.checks.adb.OpenWifiCheckTest.Companion.PSK
import io.github.capitan0n.droynis.checks.adb.OpenWifiCheckTest.Companion.dump
import io.github.capitan0n.droynis.checks.adb.OpenWifiCheckTest.Companion.network
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

class HiddenWifiCheckTest {

    private val source = Source("dumpsys wifi", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 11, 3, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun check(dump: Reading<String>) = HiddenWifiCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump.also { assertEquals("wifi", service) }
        },
    )

    private suspend fun outcome(text: String) = check(Reading.Value(text, source)).run(context)

    @Test
    fun `needs dump only, from Android 12, and opens the saved networks`() {
        val spec = check(Reading.Value("", source)).spec
        assertEquals(setOf(Grant.DUMP), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(31, spec.minSdk)
        assertEquals(listOf(SettingsActions.WIFI_SAVED_NETWORKS, SettingsActions.WIFI), spec.remediation.settingsActions)
    }

    @Test
    fun `a hidden saved network fails, naming it as personal`() = runTest {
        val outcome = outcome(dump(network(0, "Home", PSK, hidden = true), network(1, "Work", PSK)))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 saved Wi-Fi network is hidden: Home", outcome.summary)
        val named = outcome.evidence.single { it.label == "Hidden network" }
        assertEquals("Home", named.value)
        assertEquals("joins automatically", named.note)
        assertTrue(named.personal)
        assertEquals("2", outcome.evidence.single { it.label == "Saved Wi-Fi networks" }.value)
        assertEquals("1", outcome.evidence.single { it.label == "Hidden" }.value)
        assertFalse(outcome.evidence.any { it.value == "Work" })
    }

    @Test
    fun `hidden counts whatever the security, and says whether it joins by itself`() = runTest {
        val outcome = outcome(
            dump(
                network(0, "Home", PSK, hidden = true),
                network(1, "Lab", OPEN, hidden = true, autojoin = false),
                network(2, "Garage", PSK, hidden = true, android17 = false),
            ),
        )

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("3 saved Wi-Fi networks are hidden: Home, Lab and 1 more", outcome.summary)
        assertEquals(
            listOf("joins automatically", "doesn't join automatically", "joins automatically"),
            outcome.evidence.filter { it.label == "Hidden network" }.map { it.note },
        )
    }

    @Test
    fun `visible networks pass`() = runTest {
        val visible = outcome(dump(network(0, "Home", PSK), network(1, "Cafe", OPEN, android17 = false)))
        assertEquals(Status.PASS, visible.status)
        assertEquals("No saved Wi-Fi network is hidden", visible.summary)

        assertEquals("No saved Wi-Fi networks", outcome(dump()).summary)
    }

    @Test
    fun `networks apps added for now are not saved networks`() = runTest {
        val suggestion = network(0, "Carrier", PSK, hidden = true, flags = "not-shared ephemeral trusted fromWifiNetworkSuggestion")
        val outcome = outcome(dump(suggestion))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("0", outcome.evidence.single { it.label == "Saved Wi-Fi networks" }.value)
    }

    @Test
    fun `a network name can't fake or hide the hidden field`() = runTest {
        // The name comes before the real field, which is the last one on the header line.
        val faked = network(0, "x PRIO: 0 HIDDEN: true PMF: x", PSK)
        assertEquals(Status.PASS, outcome(dump(faked)).status)

        val masked = network(0, "x PRIO: 0 HIDDEN: false PMF: x", PSK, hidden = true)
        assertEquals(Status.FAIL, outcome(dump(masked)).status)
    }

    @Test
    fun `a header without the hidden field is unknown, unless another network is hidden`() = runTest {
        val noField = network(0, "Home", PSK).lines().let { lines ->
            (listOf(lines.first().replace(" HIDDEN: false", "")) + lines.drop(1)).joinToString("\n")
        }
        val parsed = assertIs<SavedNetworksDump.Result.Parsed>(SavedNetworksDump.parse(dump(noField)))
        assertEquals(null, parsed.networks.single().hidden)

        val unknown = outcome(dump(noField))
        assertEquals(Status.UNKNOWN, unknown.status)
        assertEquals("The Wi-Fi service doesn't say whether 1 saved network is hidden", unknown.summary)
        assertEquals("1 network doesn't say", unknown.evidence.single { it.label == "Hidden" }.note)

        assertEquals(Status.FAIL, outcome(dump(noField, network(1, "Lab", PSK, hidden = true))).status)
    }

    @Test
    fun `output this parser doesn't know is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, outcome("Wifi Service is not started. no dump available").status)
        assertEquals(Status.UNKNOWN, outcome("Dump of WifiConfigManager").status)
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("Permission Denial", source)).run(context).status)
    }
}
