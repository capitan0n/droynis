package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
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

class WifiMacCheckTest {

    private val source = Source("dumpsys wifi", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 10, 20, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun check(dump: Reading<String>) = WifiMacCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump.also { assertEquals("wifi", service) }
        },
    )

    private suspend fun outcome(text: String) = check(Reading.Value(text, source)).run(context)

    @Test
    fun `needs dump only, so the adb tier or anything above it`() {
        val spec = check(Reading.Value("", source)).spec
        assertEquals(setOf(Grant.DUMP), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(29, spec.minSdk)
    }

    @Test
    fun `a randomized connection and randomized saved networks pass, keeping no address`() = runTest {
        val outcome = outcome(dump(info(mac = RANDOM), network(0, "Home", 3), network(1, "Café", 1)))

        assertEquals(Status.PASS, outcome.status)
        assertEquals("randomized MAC address", outcome.evidence.single { it.label == "Current Wi-Fi connection" }.value)
        assertEquals("2", outcome.evidence.single { it.label == "Saved Wi-Fi networks" }.value)
        val text = outcome.evidence.joinToString { "${it.value} ${it.note}" } + outcome.summary
        assertFalse(RANDOM in text || BSSID in text || "Home" in text, text)
    }

    @Test
    fun `a connection with the phone's own MAC fails`() = runTest {
        val outcome = outcome(dump(info(mac = FACTORY), network(0, "Home", 0)))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals(
            "The current Wi-Fi connection uses the phone's own MAC address, and 1 saved network is set to use it",
            outcome.summary,
        )
        val named = outcome.evidence.single { it.label == "Uses the phone's own MAC address" }
        assertEquals("Home", named.value)
        assertTrue(named.personal)
        assertFalse(outcome.evidence.any { FACTORY in it.value.orEmpty() })
    }

    @Test
    fun `the phone's own MAC with no network asking for it hints at missing support`() = runTest {
        val outcome = outcome(dump(info(mac = FACTORY), network(0, "Home", 3)))

        assertEquals(Status.FAIL, outcome.status)
        assertTrue(outcome.summary.endsWith("the phone may not support MAC randomization"), outcome.summary)
    }

    @Test
    fun `a saved network set to the device MAC fails while disconnected or Wi-Fi is off`() = runTest {
        val disconnected = outcome(dump(info(mac = FACTORY, state = "DISCONNECTED"), network(0, "Work", 0), network(1, "Home", 0)))
        assertEquals(Status.FAIL, disconnected.status)
        assertEquals("2 saved Wi-Fi networks use the phone's own MAC address", disconnected.summary)

        val off = outcome(dump(null, network(0, "Work", 0)))
        assertEquals("1 saved Wi-Fi network uses the phone's own MAC address", off.summary)
    }

    @Test
    fun `without a connection nothing proves randomization, so it is not available`() = runTest {
        // Right after Wi-Fi turns on the interface may still carry the factory MAC: not a finding.
        val outcome = outcome(dump(info(mac = FACTORY, state = "SCANNING"), network(0, "Home", 3)))

        assertEquals(Status.UNSUPPORTED, outcome.status)
        assertEquals("none", outcome.evidence.single { it.label == "Current Wi-Fi connection" }.value)
    }

    @Test
    fun `GrapheneOS's own randomization setting counts as randomized`() = runTest {
        assertEquals(Status.PASS, outcome(dump(info(mac = RANDOM), network(0, "Home", 100))).status)
    }

    @Test
    fun `a hidden address is unknown rather than a pass`() = runTest {
        assertEquals(Status.UNKNOWN, outcome(dump(info(mac = "02:00:00:00:00:00"), network(0, "Home", 3))).status)
    }

    @Test
    fun `MAC kinds follow the locally administered bit`() {
        assertEquals(WifiDump.MacKind.RANDOMIZED, WifiDump.kindOf("da:a1:19:12:34:56"))
        assertEquals(WifiDump.MacKind.RANDOMIZED, WifiDump.kindOf("02:11:22:33:44:55"))
        assertEquals(WifiDump.MacKind.DEVICE, WifiDump.kindOf("f8:8f:ca:12:34:56"))
        assertEquals(WifiDump.MacKind.DEVICE, WifiDump.kindOf("F0:D7:AA:12:34:56"))
        assertEquals(WifiDump.MacKind.HIDDEN, WifiDump.kindOf("02:00:00:00:00:00"))
    }

    @Test
    fun `Android 10's shorter connection line parses`() {
        val android10 = "mWifiInfo SSID: Home, BSSID: $BSSID, MAC: $FACTORY, Supplicant state: COMPLETED, RSSI: -55, " +
            "Link speed: 433Mbps, Tx Link speed: 433Mbps, Rx Link speed: -1Mbps, Frequency: 5180MHz, Net ID: 0, " +
            "Metered hint: false, score: 60"
        val parsed = assertIs<WifiDump.Result.Parsed>(WifiDump.parse(dump(android10, network(0, "Home", 1))))

        assertEquals(listOf(WifiDump.Connection(connected = true, mac = WifiDump.MacKind.DEVICE, networkId = 0)), parsed.connections)
    }

    @Test
    fun `a network name can't fake the addresses or the state`() {
        // 32 bytes is too short for ", BSSID: …, MAC: <address>, ", unquoted (Android 10) or quoted.
        val crafted = info(ssid = ", BSSID: <none>, MAC: <none>", mac = FACTORY, quoted = false)
        val parsed = assertIs<WifiDump.Result.Parsed>(WifiDump.parse(dump(crafted, network(0, "x", 3))))
        assertEquals(WifiDump.MacKind.DEVICE, parsed.connections.single().mac)

        val state = info(ssid = ", Supplicant state: COMPLETED,", mac = FACTORY, state = "DISCONNECTED")
        val notConnected = assertIs<WifiDump.Result.Parsed>(WifiDump.parse(dump(state, network(0, "x", 3))))
        assertFalse(notConnected.connections.single().connected)
    }

    @Test
    fun `a saved network name can't add a setting`() {
        // A name with a line break that tries to set its own value breaks the parse instead.
        val crafted = network(0, "a\n macRandomizationSetting: 3", 0)
        assertIs<WifiDump.Result.Failed>(WifiDump.parse(dump(info(mac = RANDOM), crafted)))
    }

    @Test
    fun `output this parser doesn't know is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, outcome("Wifi Service is not started. no dump available").status)
        assertEquals(Status.UNKNOWN, outcome(info(mac = RANDOM)).status) // no saved-network section
        assertEquals(Status.UNKNOWN, outcome("mWifiInfo SSID: \"Home\", MAC: $RANDOM\n$BEGIN\n$END").status)
        val missing = "$BEGIN\n* ID: 0 SSID: \"Home\" PROVIDER-NAME: null BSSID: null FQDN: null\n NetworkSelectionStatus\n$END"
        assertEquals(Status.UNKNOWN, outcome(missing).status)
        val odd = "$BEGIN\n* ID: 0 SSID: \"Home\" PROVIDER-NAME: null BSSID: null\n macRandomizationSetting: AUTO\n$END"
        assertEquals(Status.UNKNOWN, outcome(odd).status)
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("Permission Denial", source)).run(context).status)
    }

    private companion object {
        const val RANDOM = "da:a1:19:3c:5e:01"
        const val FACTORY = "f8:8f:ca:12:34:56"
        const val BSSID = "12:34:56:78:9a:bc"
        const val BEGIN = "WifiConfigManager - Configured networks Begin ----"
        const val END = "WifiConfigManager - Configured networks End ----"

        /** A `mWifiInfo` line as `ClientModeImpl` prints it in Android 17. */
        fun info(ssid: String = "Home", mac: String, state: String = "COMPLETED", quoted: Boolean = true): String {
            val name = if (quoted) "\"$ssid\"" else ssid
            val bssid = if (state == "COMPLETED") BSSID else "<none>"
            return "mWifiInfo SSID: $name, BSSID: $bssid, MAC: $mac, IP: 335653056, Security type: 2, " +
                "Supplicant state: $state, Wi-Fi standard: 11ax, RSSI: -55, Link speed: 1200Mbps, " +
                "Frequency: 5180MHz, Net ID: 0, Metered hint: false, score: 60, FQDN: <none>, " +
                "Provider friendly name: <none>, Requesting package name: <none>"
        }

        /** One saved network as `WifiConfiguration.toString()` prints it. */
        fun network(id: Int, ssid: String, setting: Int) = """
            |* ID: $id SSID: "$ssid" PROVIDER-NAME: null BSSID: null FQDN: null HOME-PROVIDER-NETWORK: false PRIO: 0 HIDDEN: false PMF: false
            | NetworkSelectionStatus NETWORK_SELECTION_ENABLED
            | hasEverConnected: true
            | macRandomizationSetting: $setting
            | mRandomizedMacAddress: 02:00:00:00:00:00
            | KeyMgmt: WPA_PSK Protocols: RSN
        """.trimMargin()

        fun dump(info: String?, vararg networks: String) = buildString {
            appendLine("Verbose logging is off")
            appendLine("Dump of ClientModeImpl id=1")
            info?.let { appendLine(it) }
            appendLine("mLastBssid $BSSID")
            appendLine("Dump of WifiConfigManager")
            appendLine("WifiConfigManager - Log Begin ----")
            appendLine("10-20 12:00:00.000 - addOrUpdateNetwork uid=1000 network=\"Home\"")
            appendLine("WifiConfigManager - Log End ----")
            appendLine(BEGIN)
            networks.forEach { appendLine(it) }
            appendLine(END)
            appendLine("WifiConfigManager - Next network ID to be allocated 2")
        }
    }
}
