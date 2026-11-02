package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import io.github.capitan0n.droynis.core.Tier
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

/** Hotspot security (NETW-3103). */
class HotspotCheckTest {

    private val source = Source("dumpsys wifi", Grant.DUMP)
    private val context = ScanContext(ZonedDateTime.of(2026, 11, 2, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun check(dump: Reading<String>) = HotspotCheck(
        object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump.also { assertEquals("wifi", service) }
        },
    )

    private suspend fun outcome(text: String): Outcome = check(Reading.Value(text, source)).run(context)

    @Test
    fun `needs dump only, from Android 14`() {
        val spec = check(Reading.Value("", source)).spec
        assertEquals("NETW-3103", spec.id)
        assertEquals(setOf(Grant.DUMP), spec.requires)
        assertEquals(Tier.ADB, spec.requiredTier)
        assertEquals(34, spec.minSdk)
    }

    @Test
    fun `a password hotspot that turns itself off passes, keeping no name`() = runTest {
        val outcome = outcome(dump(config(security = HotspotDump.WPA3_SAE_TRANSITION)))

        assertEquals(Status.PASS, outcome.status)
        assertEquals("The hotspot uses WPA2/WPA3-Personal and turns off by itself when no device is connected", outcome.summary)
        assertEquals(listOf("WPA2/WPA3-Personal", "set", "on"), outcome.evidence.map { it.value })
        assertEquals("after Android's default time with no device connected", outcome.evidence.last().note)
        assertFalse(outcome.evidence.any { "Pixel" in it.toString() || "12:34:56" in it.toString() })

        // WPA2 alone still needs the password: not a finding.
        assertEquals(Status.PASS, outcome(dump(config(security = HotspotDump.WPA2_PSK))).status)
        assertEquals(Status.PASS, outcome(dump(config(security = HotspotDump.WPA3_SAE))).status)
    }

    @Test
    fun `no password is a warning, Enhanced Open included`() = runTest {
        val open = outcome(dump(config(security = HotspotDump.OPEN, password = "<empty>")))
        assertEquals(Status.FAIL, open.status)
        assertEquals(Severity.WARNING, open.escalation)
        assertEquals("The hotspot has no password: anyone in range can join it", open.summary)
        assertEquals("None", open.evidence.first().value)

        val owe = outcome(dump(config(security = HotspotDump.OWE, password = "<empty>")))
        assertEquals(Status.FAIL, owe.status)
        assertEquals(Severity.WARNING, owe.escalation)
        assertEquals("The hotspot has no password (Enhanced Open): anyone in range can join it", owe.summary)
        val fallback = outcome(dump(config(security = HotspotDump.OWE_TRANSITION, password = "<empty>")))
        assertEquals(Severity.WARNING, fallback.escalation)
    }

    @Test
    fun `a hotspot that stays on is a notice, both together a warning`() = runTest {
        val stays = outcome(dump(config(autoShutdown = false)))
        assertEquals(Status.FAIL, stays.status)
        assertNull(stays.escalation)
        assertEquals("The hotspot uses WPA2/WPA3-Personal, but doesn't turn off by itself when no device is connected", stays.summary)
        assertNull(stays.evidence.last().note)

        val both = outcome(dump(config(security = HotspotDump.OPEN, password = "<empty>", autoShutdown = false)))
        assertEquals(Severity.WARNING, both.escalation)
        assertEquals("The hotspot has no password and doesn't turn off by itself", both.summary)
    }

    @Test
    fun `the delay is shown as Settings would think of it`() = runTest {
        assertEquals("after 5 minutes with no device connected", outcome(dump(config(timeout = 300_000))).evidence.last().note)
        assertEquals("after 30 seconds with no device connected", outcome(dump(config(timeout = 30_000))).evidence.last().note)
        // Legacy callers stored 0 for the default.
        assertEquals("after Android's default time with no device connected", outcome(dump(config(timeout = 0))).evidence.last().note)
    }

    @Test
    fun `settings that don't add up, or an unknown type, are unknown`() = runTest {
        assertEquals(Status.UNKNOWN, outcome(dump(config(security = 9))).status)
        assertEquals(Status.UNKNOWN, outcome(dump(config(security = HotspotDump.WPA2_PSK, password = "<empty>"))).status)
        assertEquals(Status.UNKNOWN, outcome(dump(config(security = HotspotDump.OPEN))).status)
    }

    @Test
    fun `a crafted hotspot name can't fake a field`() = runTest {
        // A name that adds a field line repeats that field.
        assertEquals(Status.UNKNOWN, outcome(dump(config(security = HotspotDump.OPEN, password = "<empty>", ssid = "\"x\n SecurityType = 3\""))).status)
        assertEquals(Status.UNKNOWN, outcome(dump(config(security = HotspotDump.OPEN, password = "<empty>", ssid = "\"x\n SecurityType = 3\n\""))).status)
        // A name that ends the block early leaves the fields out.
        assertEquals(Status.UNKNOWN, outcome(dump(config(ssid = "\"x\n\n\""))).status)
        // A second header, say from a nearby network's name elsewhere in the dump, makes it ambiguous.
        assertEquals(Status.UNKNOWN, outcome(dump(config()) + "\n${HotspotDump.PREFIX}ssid = \"x\"").status)
    }

    @Test
    fun `output this parser doesn't know is unknown`() = runTest {
        // Android 13 and older print no hotspot settings.
        assertEquals(Status.UNKNOWN, outcome(dump("")).status)
        assertEquals(Status.UNKNOWN, outcome("Wifi Service is not started. no dump available").status)
        assertEquals(Status.UNKNOWN, outcome(dump("${HotspotDump.PREFIX}null")).status)
        assertEquals(Status.UNKNOWN, outcome(dump(config().lines().filterNot { "AutoShutdownEnabled" in it }.joinToString("\n"))).status)
        assertEquals(Status.UNKNOWN, outcome(dump(config().replace("AutoShutdownEnabled = true", "AutoShutdownEnabled = yes"))).status)
        assertEquals(Status.UNKNOWN, outcome(dump(config().replace("<non-empty>", "secret"))).status)
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("Permission Denial", source)).run(context).status)
    }

    @Test
    fun `the same dump still parses for the other Wi-Fi checks`() {
        val text = dump(config())
        assertIs<WifiDump.Result.Parsed>(WifiDump.parse(text))
        assertIs<SavedNetworksDump.Result.Parsed>(SavedNetworksDump.parse(text))
        val parsed = assertIs<HotspotDump.Result.Parsed>(HotspotDump.parse(text))
        assertEquals(HotspotDump.Hotspot(HotspotDump.WPA3_SAE_TRANSITION, true, true, -1), parsed.hotspot)
    }

    private companion object {
        /** `SoftApConfiguration.toString()` after the dump's prefix, Android 17. */
        fun config(
            security: Int = HotspotDump.WPA3_SAE_TRANSITION,
            password: String = "<non-empty>",
            autoShutdown: Boolean = true,
            timeout: Long = -1,
            ssid: String = "\"Pixel 9\"",
        ) = listOf(
            "${HotspotDump.PREFIX}ssid = $ssid ",
            " Passphrase = $password ",
            " HiddenSsid = false ",
            " Channels = {1=0} ",
            " SecurityType = $security ",
            " MaxClient = 0 ",
            " AutoShutdownEnabled = $autoShutdown ",
            " ShutdownTimeoutMillis = $timeout ",
            " ClientControlByUser = false ",
            " BlockedClientList = [] ",
            " AllowedClientList= [] ",
            " MacRandomizationSetting = 1 ",
            " BridgedModeInstanceOpportunisticEnabled = true ",
            " BridgedModeOpportunisticShutdownTimeoutMillis = -1 ",
            " Ieee80211axEnabled = true ",
            " Ieee80211beEnabled = true ",
            " isUserConfiguration = true ",
            " vendorElements = [] ",
            " mPersistentRandomizedMacAddress = 12:34:56:78:9a:bc ",
            " mAllowedAcsChannels2g = [] ",
            " mAllowedAcsChannels5g = [] ",
            " mAllowedAcsChannels6g = [] ",
            " mMaxChannelBandwidth = 0 ",
            " mVendorData = [] ",
            " mIsClientIsolationEnabled = false ",
            " mIsBandOptimizationEnabled = true",
        ).joinToString("\n")

        /** The parts of `dumpsys wifi` around the hotspot settings. */
        fun dump(config: String) = listOf(
            "Verbose logging is off",
            "mWifiInfo SSID: \"Home\", BSSID: 12:34:56:78:9a:bc, MAC: da:a1:19:00:00:01, IP: /192.168.1.20, " +
                "Security type: 2, Supplicant state: COMPLETED, Wi-Fi standard: 11ax, Net ID: 0,",
            "WifiConfigManager - Configured networks Begin ----",
            "WifiConfigManager - Configured networks End ----",
            "",
            config,
            "",
            "Dump of PasspointManager",
        ).joinToString("\n")
    }
}
