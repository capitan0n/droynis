package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZoneOffset
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PersonalDetailsTest {

    private val source = Source("test")

    private fun finding(summary: String, vararg evidence: Evidence) = Finding(
        spec = CheckSpec("NETW-3001", Category.NETWORK, "Private DNS", Severity.WARNING, "Why.", Remediation("Fix.")),
        status = Status.PASS,
        severity = Severity.WARNING,
        summary = summary,
        evidence = evidence.toList(),
        elapsedMillis = 1,
    )

    @Test
    fun `personal evidence is hidden, and so is its value where the summary repeats it`() {
        val hidden = PersonalDetails.hide(
            listOf(
                finding(
                    "Private DNS is active: abc123.dns.nextdns.io",
                    Evidence("Private DNS server", "abc123.dns.nextdns.io", source, personal = true),
                    Evidence("Transports", "WIFI", source),
                ),
            ),
        ).single()

        assertEquals("Private DNS is active: [hidden]", hidden.summary)
        assertEquals("[hidden]", hidden.evidence[0].value)
        assertEquals("WIFI", hidden.evidence[1].value)
    }

    @Test
    fun `a short personal value is hidden where it stands alone`() {
        val hidden = PersonalDetails.hide(
            listOf(
                finding(
                    "1 computer is trusted for USB debugging: pc",
                    Evidence("Trusted computer", "pc", source, personal = true),
                ),
            ),
        ).single()

        assertEquals("1 computer is trusted for USB debugging: [hidden]", hidden.summary)
        assertEquals("[hidden]", hidden.evidence.single().value)
    }

    @Test
    fun `every IP and MAC address is masked, but not times, versions or the any address`() {
        assertEquals("[hidden], [hidden]", PersonalDetails.mask("192.168.1.1, 9.9.9.9"))
        assertEquals("TCP 5555 on [hidden], UDP 53 on 0.0.0.0", PersonalDetails.mask("TCP 5555 on 192.168.1.42, UDP 53 on 0.0.0.0"))
        assertEquals("addresses [hidden]/24 and [hidden]/64.", PersonalDetails.mask("addresses 192.168.1.42/24 and fe80::1c2b:3aff:fe4d:5e6f/64."))
        assertEquals("proxy [hidden]:3128", PersonalDetails.mask("proxy 10.0.0.8:3128"))
        assertEquals("on [hidden]", PersonalDetails.mask("on ::ffff:192.168.1.7"))
        assertEquals("MAC [hidden]", PersonalDetails.mask("MAC 02:1a:2b:3c:4d:5e"))
        assertEquals("TCP 8080 on :: and ::1", PersonalDetails.mask("TCP 8080 on :: and ::1"))

        val untouched = "WebView 141.0.7390.122, used 2026-10-05 11:59:59, Android 16, kernel 6.6.89, 127.0.0.1"
        assertEquals(untouched, PersonalDetails.mask(untouched))
    }

    @Test
    fun `reports say whether personal details are hidden`() {
        val findings = listOf(
            finding(
                "1 computer is trusted for USB debugging: alexandros@manjaro",
                Evidence("Trusted computer", "alexandros@manjaro", source, note = "fingerprint AB:CD:EF:01", personal = true),
            ),
        )
        val context = ScanContext(ZonedDateTime.of(2026, 10, 7, 9, 0, 0, 0, ZoneOffset.UTC), sdkInt = 30)
        val index = HardeningIndex.of(findings)

        val hidden = JsonReport.render(context, findings, index, emptyList(), "0.12.0", hidePersonal = true)
        assertTrue("\"personalDetails\": \"hidden\"" in hidden)
        assertFalse("alexandros" in hidden)
        assertFalse("AB:CD" in hidden)
        val included = JsonReport.render(context, findings, index, emptyList(), "0.12.0")
        assertTrue("\"personalDetails\": \"included\"" in included)
        assertTrue("alexandros@manjaro" in included)
        assertTrue("\"personal\": true" in included)

        val markdown = MarkdownReport.render(context, findings, index, emptyList(), "0.12.0", hidePersonal = true)
        assertTrue("Personal details hidden: ${PersonalDetails.DESCRIPTION}" in markdown)
        assertFalse("alexandros" in markdown)
        assertFalse("Personal details hidden" in MarkdownReport.render(context, findings, index, emptyList(), "0.12.0"))
    }
}
