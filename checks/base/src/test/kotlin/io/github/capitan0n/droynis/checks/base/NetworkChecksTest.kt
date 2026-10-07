package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Status
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class NetworkChecksTest {

    private suspend fun privateDns(snapshot: NetworkSnapshot?) = PrivateDnsCheck(FakeNetwork(value(snapshot))).outcome()

    @Test
    fun `private dns`() = runTest {
        assertEquals("Private DNS is active: dns.quad9.net", privateDns(wifi(true, "dns.quad9.net")).summary)
        assertEquals("Private DNS is active (automatic mode)", privateDns(wifi(true)).summary)
        assertEquals(Status.FAIL, privateDns(wifi(false)).status)
        assertEquals(Status.PASS, privateDns(wifi(false, vpn = true)).status) // DNS rides the tunnel
        assertEquals(Status.UNKNOWN, privateDns(null).status) // offline
        assertEquals(Status.UNKNOWN, privateDns(wifi(null)).status) // not reported
        assertEquals(Status.UNKNOWN, PrivateDnsCheck(FakeNetwork(unavailable())).status())
    }

    @Test
    fun `private dns evidence lists the resolvers`() = runTest {
        val evidence = privateDns(wifi(false)).evidence.associate { it.label to it.value }

        assertEquals("192.168.1.1", evidence["DNS servers"])
        assertEquals("WIFI", evidence["Transports"])
    }

    @Test
    fun `vpn`() = runTest {
        assertEquals(Status.PASS, VpnCheck(FakeNetwork(value(wifi(vpn = true)))).status())
        assertEquals(Status.FAIL, VpnCheck(FakeNetwork(value(wifi()))).status())
        assertEquals(Status.UNKNOWN, VpnCheck(FakeNetwork(value(null))).status())
    }

    @Test
    fun `wifi security`() = runTest {
        suspend fun outcome(snapshot: NetworkSnapshot?) = WifiSecurityCheck(FakeNetwork(value(snapshot))).outcome()

        assertEquals(Status.PASS, outcome(wifi(security = WifiSecurity.WPA3_PERSONAL)).status)
        assertEquals("Wi-Fi is encrypted: WPA/WPA2-Personal", outcome(wifi()).summary)
        assertEquals(Status.PASS, outcome(wifi(security = WifiSecurity.OWE)).status)
        assertEquals(Status.FAIL, outcome(wifi(security = WifiSecurity.OPEN)).status)
        assertEquals(Status.FAIL, outcome(wifi(security = WifiSecurity.WEP)).status)
        assertEquals(Status.PASS, outcome(wifi(security = WifiSecurity.OPEN, vpn = true)).status) // tunnelled
        assertEquals(Status.UNKNOWN, outcome(wifi(security = null)).status)
        assertEquals(Status.UNKNOWN, outcome(wifi(security = WifiSecurity.UNKNOWN)).status)
        assertEquals(Status.UNSUPPORTED, outcome(cellular()).status)
        assertEquals(Status.UNKNOWN, outcome(null).status)
        assertEquals(31, WifiSecurityCheck(FakeNetwork(value(null))).spec.minSdk)
    }

    @Test
    fun `network evidence shows the wifi security only on wifi`() = runTest {
        fun labels(snapshot: NetworkSnapshot) = networkEvidence(value(snapshot)).map { it.label }

        val evidence = networkEvidence(value(wifi(security = WifiSecurity.OPEN))).associate { it.label to it.value }
        assertEquals("open, no encryption", evidence["Wi-Fi security"])
        assertEquals("none", evidence["HTTP proxy"])
        assertEquals(false, "Wi-Fi security" in labels(cellular()))
    }

    @Test
    fun `http proxy`() = runTest {
        suspend fun outcome(snapshot: NetworkSnapshot?) = HttpProxyCheck(FakeNetwork(value(snapshot))).outcome()

        assertEquals(Status.PASS, outcome(wifi()).status)
        val proxied = outcome(wifi().copy(httpProxy = "10.0.0.8:3128"))
        assertEquals(Status.FAIL, proxied.status)
        assertEquals("Web traffic on Wi-Fi goes through the proxy 10.0.0.8:3128", proxied.summary)
        assertEquals(Status.UNKNOWN, outcome(null).status)
    }

    @Test
    fun `nfc`() = runTest {
        assertEquals(Status.FAIL, NfcCheck(FakeRadios(value(true))).status())
        assertEquals(Status.PASS, NfcCheck(FakeRadios(value(false))).status())
        assertEquals(Status.UNSUPPORTED, NfcCheck(FakeRadios(unsupported("no NFC hardware"))).status())
    }

    @Test
    fun `user certificates`() = runTest {
        assertEquals(Status.PASS, UserCertificatesCheck(FakeCertificates()).status())

        val certs = listOf(UserCertificate("School Proxy CA", LocalDate.of(2030, 1, 1)))
        val outcome = UserCertificatesCheck(FakeCertificates(value(certs))).outcome()
        assertEquals(Status.FAIL, outcome.status)
        assertEquals("1 user CA certificate installed: School Proxy CA", outcome.summary)
        assertEquals("School Proxy CA (expires 2030-01-01)", outcome.evidence.single().value)
    }

    @Test
    fun `bluetooth`() = runTest {
        fun check(raw: String?) = BluetoothCheck(FakeSettings(global = mapOf("bluetooth_on" to value(raw))))

        assertEquals(Status.FAIL, check("1").status())
        assertEquals(Status.FAIL, check("2").status()) // on while in airplane mode
        assertEquals(Status.PASS, check("0").status())
        assertEquals(Status.UNKNOWN, check(null).status())
    }

    @Test
    fun `location`() = runTest {
        assertEquals(Status.FAIL, LocationCheck(FakeRadios(location = value(true))).status())
        assertEquals(Status.PASS, LocationCheck(FakeRadios(location = value(false))).status())
        assertEquals(Status.UNKNOWN, LocationCheck(FakeRadios(location = unavailable("no service"))).status())
    }

    @Test
    fun `wifi and bluetooth scanning`() = runTest {
        fun check(wifi: Reading<String?>, ble: Reading<String?>) = ScanningCheck(
            FakeSettings(global = mapOf("wifi_scan_always_enabled" to wifi, "ble_scan_always_enabled" to ble)),
        )

        val both = check(value("1"), value("1")).outcome()
        assertEquals(Status.FAIL, both.status)
        assertEquals("Wi-Fi scanning and Bluetooth scanning are on", both.summary)
        assertEquals("Bluetooth scanning is on", check(value("0"), value("1")).outcome().summary)
        // One switch on is enough to fail, even when the other can't be read.
        assertEquals(Status.FAIL, check(unavailable("access denied"), value("1")).status())
        assertEquals(Status.PASS, check(value("0"), value("0")).status())

        val unread = check(value("0"), unavailable("access denied")).outcome()
        assertEquals(Status.UNKNOWN, unread.status)
        assertEquals("Could not tell whether Bluetooth scanning is on", unread.summary)
        assertEquals(Status.UNKNOWN, check(value(null), value("0")).status())
    }
}
