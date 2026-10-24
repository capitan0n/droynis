package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.AdminApp
import io.github.capitan0n.droynis.checks.base.DevicePolicy
import io.github.capitan0n.droynis.checks.base.EncryptionStatus
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
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class OpenWifiCheckTest {

    private val source = Source("dumpsys wifi", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 10, 20, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun policy(protection: Reading<Boolean>) = object : DevicePolicy {
        var asked = false
        override fun encryptionStatus(): Reading<EncryptionStatus> = Reading.Unavailable("unused", source)
        override fun activeAdmins(): Reading<List<AdminApp>> = Reading.Unavailable("unused", source)
        override fun advancedProtection(): Reading<Boolean> = protection.also { asked = true }
    }

    private fun check(dump: Reading<String>, protection: Reading<Boolean> = Reading.Value(false, source)) = OpenWifiCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump.also { assertEquals("wifi", service) }
        },
        policy(protection),
    )

    private suspend fun outcome(text: String, protection: Reading<Boolean> = Reading.Value(false, source)) =
        check(Reading.Value(text, source), protection).run(context)

    @Test
    fun `needs dump only, from Android 12`() {
        val spec = check(Reading.Value("", source)).spec
        assertEquals(setOf(Grant.DUMP), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(31, spec.minSdk)
    }

    @Test
    fun `an open network that joins by itself fails, naming it as personal`() = runTest {
        val outcome = outcome(dump(network(0, "Home", PSK), network(1, "Airport Free WiFi", OPEN)))

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 saved Wi-Fi network without a password joins automatically: Airport Free WiFi", outcome.summary)
        val named = outcome.evidence.single { it.label == "Joins automatically" }
        assertEquals("Airport Free WiFi", named.value)
        assertEquals("open", named.note)
        assertTrue(named.personal)
        assertEquals("2", outcome.evidence.single { it.label == "Saved Wi-Fi networks" }.value)
        assertFalse(outcome.evidence.any { it.value == "Home" })
    }

    @Test
    fun `password networks, and open ones that don't join by themselves, pass`() = runTest {
        val secure = outcome(dump(network(0, "Home", PSK), network(1, "Work", listOf(3 to true))))
        assertEquals(Status.PASS, secure.status)
        assertEquals("Every saved Wi-Fi network needs a password", secure.summary)

        val manual = outcome(dump(network(0, "Home", PSK), network(1, "Cafe", OPEN, autojoin = false)))
        assertEquals(Status.PASS, manual.status)
        assertEquals("Saved Wi-Fi networks without a password don't join automatically", manual.summary)

        assertEquals("No saved Wi-Fi networks", outcome(dump()).summary)
    }

    @Test
    fun `Enhanced Open and WEP count as no password, an upgraded open network once`() = runTest {
        val outcome = outcome(
            dump(
                network(0, "Library", listOf(6 to true)),
                network(1, "Old Router", listOf(1 to true)),
                network(2, "Station", listOf(0 to true, 6 to true)),
                // WPA2 auto-upgraded to WPA3: still needs the password.
                network(3, "Home", listOf(2 to true, 4 to true)),
            ),
        )

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("3 saved Wi-Fi networks without a password join automatically: Library, Old Router and 1 more", outcome.summary)
        assertEquals(
            listOf("Enhanced Open", "WEP", "open or Enhanced Open"),
            outcome.evidence.filter { it.label == "Joins automatically" }.map { it.note },
        )
    }

    @Test
    fun `a disabled open fallback no longer counts`() = runTest {
        // After a transition-disable indication Android keeps only the Enhanced Open parameters enabled.
        val parsed = assertIs<SavedNetworksDump.Result.Parsed>(
            SavedNetworksDump.parse(dump(network(0, "Station", listOf(0 to false, 6 to true)))),
        )
        assertEquals(setOf(6), parsed.networks.single().securityTypes)
        val passwordOnly = network(1, "Home", listOf(2 to true, 0 to false))
        assertEquals(Status.PASS, outcome(dump(passwordOnly)).status)
    }

    @Test
    fun `networks apps added for now are not saved networks`() = runTest {
        val outcome = outcome(
            dump(
                network(0, "Carrier Hotspot", OPEN, flags = "not-shared ephemeral trusted fromWifiNetworkSuggestion"),
                network(1, "App Network", OPEN, flags = "not-shared ephemeral trusted fromWifiNetworkSpecifier"),
            ),
        )
        assertEquals(Status.PASS, outcome.status)
        assertEquals("0", outcome.evidence.single { it.label == "Saved Wi-Fi networks" }.value)
    }

    @Test
    fun `Android 17 skips insecure networks under Advanced Protection, which must be read as on`() = runTest {
        val text = dump(network(0, "Cafe", OPEN, aapm = false))

        val on = outcome(text, Reading.Value(true, source))
        assertEquals(Status.PASS, on.status)
        assertEquals("Advanced Protection keeps saved Wi-Fi networks without a password from joining automatically", on.summary)
        assertEquals("Cafe", on.evidence.single { it.label == "Kept from joining by Advanced Protection" }.value)

        assertEquals(Status.FAIL, outcome(text, Reading.Value(false, source)).status)
        assertEquals(Status.FAIL, outcome(text, Reading.Unavailable("denied", source)).status)
        // A network the user allowed under Advanced Protection still joins.
        assertEquals(Status.FAIL, outcome(dump(network(0, "Cafe", OPEN, aapm = true)), Reading.Value(true, source)).status)
    }

    @Test
    fun `Advanced Protection is read only when it could matter`() = runTest {
        val protection = policy(Reading.Value(true, source))
        val text = dump(network(0, "Cafe", OPEN))
        val dumpsys = object : Dumpsys {
            override fun dump(service: String, vararg args: String): Reading<String> = Reading.Value(text, source)
        }
        assertEquals(Status.FAIL, OpenWifiCheck(dumpsys, protection).run(context).status)
        assertFalse(protection.asked)
    }

    @Test
    fun `Android 12L's shorter networks parse`() {
        val parsed = assertIs<SavedNetworksDump.Result.Parsed>(
            SavedNetworksDump.parse(dump(network(4, "Cafe", OPEN, android17 = false))),
        )
        val network = parsed.networks.single()
        assertEquals(SavedNetworksDump.SavedNetwork(4, "Cafe", setOf(0), autojoin = true, ephemeral = false), network)
        assertNull(network.autojoinWithAdvancedProtection)
    }

    @Test
    fun `the full Android 17 block still parses for the MAC randomization check`() {
        val parsed = assertIs<WifiDump.Result.Parsed>(WifiDump.parse(dump(network(0, "Home", PSK), network(1, "Cafe", OPEN))))
        assertEquals(listOf(3, 3), parsed.saved.map { it.macRandomization })
    }

    @Test
    fun `free text can't hide a network or flip its switch`() = runTest {
        // Another network's name in "connect choice" is not a flag.
        val chosen = network(0, "Cafe", OPEN, connectChoice = "\"x ephemeral allowAutojoin=false\"NONE")
        assertEquals(Status.FAIL, outcome(dump(chosen)).status)

        // An enterprise identity that repeats the switch makes the parse fail.
        val identity = network(0, "Cafe", OPEN, identity = "me allowAutojoin=false")
        assertEquals(Status.UNKNOWN, outcome(dump(identity)).status)

        // A name with a line break breaks its own header: first in the list, or after another one.
        val broken = network(0, "a\n ephemeral", OPEN)
        assertEquals(Status.UNKNOWN, outcome(dump(broken)).status)
        assertEquals(Status.UNKNOWN, outcome(dump(network(1, "Home", PSK), broken)).status)
    }

    @Test
    fun `output this parser doesn't know is unknown`() = runTest {
        assertEquals(Status.UNKNOWN, outcome("Wifi Service is not started. no dump available").status)
        assertEquals(Status.UNKNOWN, outcome("Dump of WifiConfigManager").status)
        assertEquals(Status.UNKNOWN, outcome("$BEGIN\n").status)
        val noList = "$BEGIN\n* ID: 0 SSID: \"Cafe\" PROVIDER-NAME: null BSSID: null\n allowAutojoin=true\n$END"
        assertEquals(Status.UNKNOWN, outcome(noList).status)
        val noSwitch = network(0, "Cafe", OPEN).lines().filterNot { "allowAutojoin" in it }.joinToString("\n")
        assertEquals(Status.UNKNOWN, outcome(dump(noSwitch)).status)
        val noState = network(0, "Cafe", OPEN).lines().filterNot { it.trim().startsWith("Enabled:") }.joinToString("\n")
        assertEquals(Status.UNKNOWN, outcome(dump(noState)).status)
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("Permission Denial", source)).run(context).status)
    }

    private companion object {
        const val BEGIN = "WifiConfigManager - Configured networks Begin ----"
        const val END = "WifiConfigManager - Configured networks End ----"
        val OPEN = listOf(0 to true)
        val PSK = listOf(2 to true)

        /** `SecurityParams.toString()`, Android 12L to 17. */
        fun params(type: Int, enabled: Boolean) = """
            |Security Parameters:
            | Type: $type
            | Enabled: $enabled
            | KeyMgmt: ${if (type == 0 || type == 1) "NONE" else "WPA_PSK"}
            | Protocols: RSN
            | AuthAlgorithms:
            | PairwiseCiphers: CCMP
            | GroupCiphers: CCMP
            | GroupMgmtCiphers:
            | SuiteBCiphers:
            | RequirePmf: false
            | IsAddedByAutoUpgrade: false
            | IsSaeH2eOnlyMode: false
            | IsSaePkOnlyMode: false
        """.trimMargin()

        /** One saved network as `WifiConfiguration.toString()` prints it in Android 17, or 12L. */
        fun network(
            id: Int,
            ssid: String,
            types: List<Pair<Int, Boolean>>,
            autojoin: Boolean = true,
            flags: String = "validatedInternetAccess not-shared trusted",
            aapm: Boolean? = null,
            android17: Boolean = true,
            connectChoice: String? = null,
            identity: String? = null,
        ): String = buildList {
            val (firstType, _) = types.first()
            if (android17) {
                add(
                    "ID: $id SSID: \"$ssid\" PROVIDER-NAME: null BSSID: null FQDN: null HOME-PROVIDER-NETWORK: false " +
                        "PRIO: 0 HIDDEN: false PMF: false CarrierId: -1 SubscriptionId: -1 SubscriptionGroup: null " +
                        "Currently Connected: false User Selected: true",
                )
            } else {
                add("ID: $id SSID: \"$ssid\" PROVIDER-NAME: null BSSID: null FQDN: null HOME-PROVIDER-NETWORK: false PRIO: 0 HIDDEN: false PMF: falseCarrierId: -1SubscriptionId-1")
            }
            add(" NetworkSelectionStatus NETWORK_SELECTION_ENABLED")
            add((connectChoice?.let { " connect choice: $it connect choice rssi: -60" } ?: "") + " hasEverConnected: true")
            add(" hasNeverDetectedCaptivePortal: true")
            if (android17) {
                add(" hasEverValidatedInternetAccess: true")
                // The candidate's parameters print before the list; they must not count.
                add(" mCandidateSecurityParams: " + params(firstType, true).lines().first())
                addAll(params(firstType, true).lines().drop(1))
                add(" mLastUsedSecurityParams: null numAssociation 4")
            } else {
                add(" numAssociation 4")
            }
            add(" $flags")
            add(" macRandomizationSetting: 3")
            add(" mRandomizedMacAddress: da:a1:19:3c:5e:01")
            add(" KeyMgmt: ${if (firstType == 0 || firstType == 1) "NONE" else "WPA_PSK"} Protocols: RSN")
            add(" PSK/SAE: ${if (firstType == 0) "" else "*"}")
            add("SecurityParams List:")
            types.forEach { (type, enabled) -> addAll(params(type, enabled).lines()) }
            add("")
            add("Enterprise config:")
            identity?.let { add("identity $it") }
            add("IP config:")
            add("IP assignment: DHCP")
            add("Proxy settings: NONE")
            val aapmField = aapm?.let { " mAllowedAutoJoinInAdvancedProtection=$it" } ?: ""
            add(
                " cuid=1000 cname=com.android.settings luid=1000 lname=com.android.settings lcuid=1000 " +
                    "allowAutojoin=$autojoin$aapmField noInternetAccessExpected=false mostRecentlyConnected=false ",
            )
            add("")
            add("numRebootsSinceLastUse: 0")
            add("recentFailure: Association Rejection code: 0, last update time: 0")
        }.joinToString("\n")

        fun dump(vararg networks: String) = buildString {
            appendLine("Dump of WifiConfigManager")
            appendLine("WifiConfigManager - Log Begin ----")
            appendLine("10-20 12:00:00.000 - addOrUpdateNetwork uid=1000 network=\"Cafe\"")
            appendLine("WifiConfigManager - Log End ----")
            appendLine(BEGIN)
            networks.forEach { appendLine(it) }
            appendLine(END)
            appendLine("WifiConfigManager - ConfigurationMap Begin ----")
            appendLine("WifiConfigManager - Next network ID to be allocated 5")
        }
    }
}
