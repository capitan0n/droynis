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
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class WepWifiCheckTest {

    private val source = Source("dumpsys wifi", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 11, 11, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)
    private val wep = listOf(1 to true)

    private fun check(dump: Reading<String>) = WepWifiCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump.also { assertEquals("wifi", service) }
        },
    )

    private suspend fun outcome(text: String) = check(Reading.Value(text, source)).run(context)

    @Test
    fun `needs dump only, from Android 12, and opens the saved networks`() {
        val spec = check(Reading.Value("", source)).spec
        assertEquals("NETW-3105", spec.id)
        assertEquals(setOf(Grant.DUMP), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(31, spec.minSdk)
        assertEquals(listOf(SettingsActions.WIFI_SAVED_NETWORKS, SettingsActions.WIFI), spec.remediation.settingsActions)
    }

    @Test
    fun `a saved WEP network fails whether or not it joins by itself, naming it as personal`() = runTest {
        val outcome = outcome(
            dump(network(0, "Home", PSK), network(1, "Old Router", wep), network(2, "Garage", wep, autojoin = false)),
        )

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("2 saved Wi-Fi networks use WEP: Old Router and Garage", outcome.summary)
        val named = outcome.evidence.filter { it.label == "WEP network" }
        assertEquals(listOf("Old Router", "Garage"), named.map { it.value })
        assertEquals(listOf("joins automatically", "doesn't join automatically"), named.map { it.note })
        assertTrue(named.all { it.personal })
        assertEquals("3", outcome.evidence.single { it.label == "Saved Wi-Fi networks" }.value)
        assertFalse(outcome.evidence.any { it.value == "Home" })
    }

    @Test
    fun `password and open networks pass here, and so does no network`() = runTest {
        val outcome = outcome(dump(network(0, "Home", PSK), network(1, "Cafe", OPEN)))
        assertEquals(Status.PASS, outcome.status)
        assertEquals("No saved Wi-Fi network uses WEP", outcome.summary)

        assertEquals("No saved Wi-Fi networks", outcome(dump()).summary)
    }

    @Test
    fun `a disabled WEP type and a network an app added for now don't count`() = runTest {
        val disabled = outcome(dump(network(0, "Home", listOf(2 to true, 1 to false))))
        assertEquals(Status.PASS, disabled.status)

        val ephemeral = outcome(dump(network(0, "Printer", wep, flags = "ephemeral trusted")))
        assertEquals(Status.PASS, ephemeral.status)
        assertEquals("No saved Wi-Fi networks", ephemeral.summary)
    }

    @Test
    fun `an unreadable or unrecognized dump is unknown, never passed`() = runTest {
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("Permission Denial", source)).run(context).status)
        assertEquals(Status.UNKNOWN, outcome("something else entirely").status)
    }
}
