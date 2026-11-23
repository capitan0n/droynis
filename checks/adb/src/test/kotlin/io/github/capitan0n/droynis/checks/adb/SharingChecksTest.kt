package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.ActiveTetheringCheck
import io.github.capitan0n.droynis.core.Capabilities
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZonedDateTime
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

class SharingChecksTest {
    private val context = ScanContext(ZonedDateTime.now(), sdkInt = 36, appUid = 10123)
    private val source = Source("test", Grant.DUMP)
    private fun dump(result: Reading<String>) = object : Dumpsys {
        override fun dump(service: String, vararg args: String) = result
    }

    @Test
    fun `unreadable data stays unknown and unsupported hardware is skipped`() = runTest {
        val unavailable = dump(Reading.Unavailable("permission denied", source))
        val packages = object : PackageInventory {
            override fun installedApps(): Reading<List<InstalledApp>> = error("unused")
            override fun label(packageName: String) = packageName
        }
        assertEquals(Status.UNKNOWN, PrintingServicesCheck(unavailable, packages).run(context).status)
        assertEquals(Status.UNKNOWN, PasspointCheck(unavailable) { true }.run(context).status)
        assertEquals(Status.UNSUPPORTED, PasspointCheck(unavailable) { false }.run(context).status)
        val settings = dump(Reading.Value("WifiScoringState true\nWifiPasspointState false", source))
        assertEquals("Hotspot 2.0 is off", PasspointCheck(settings) { true }.run(context).summary)
    }

    @Test
    fun `only currently tethered downstreams count`() {
        val text = """
            Tether state:
              rndis0 - TetheredState - lastError = 0
              wlan0 - LocalHotspotState - lastError = 0
              bt-pan - TetheredState - lastError = 0
              eth0 - AvailableState - lastError = 0
              unusual0 - TetheredState - lastError = 0
              Upstream wanted: true
              Current upstream interface(s): [wlan0]
            Log:
              wlan0 - TetheredState - lastError = 0
        """.trimIndent()
        assertEquals(setOf("USB", "Bluetooth", "another interface"), TetheringDump.active(text))
        assertNull(TetheringDump.active(text.replace("LocalHotspotState", "FutureState")))
        assertNull(TetheringDump.active("Tether state:\n"))
        assertEquals(emptySet(), TetheringDump.active("Tether state:\n Upstream wanted: false"))
    }

    @Test
    fun `tethering respects tier and unavailable results`() = runTest {
        val source = Source("test")
        val context = ScanContext(ZonedDateTime.now(), 32, Capabilities(setOf(Grant.SHIZUKU)))
        val check = ActiveTetheringCheck { canDump ->
            assertTrue(canDump)
            Reading.Value(setOf("Ethernet"), source)
        }
        assertEquals(Status.FAIL, check.run(context).status)
        assertEquals(Status.PASS, ActiveTetheringCheck { Reading.Value(emptySet(), source) }.run(context).status)
        assertEquals(Status.UNKNOWN, ActiveTetheringCheck { Reading.Unavailable("timeout", source) }.run(context).status)
    }

    @Test
    fun `Passpoint settings distinguish global switch and per-profile auto-join`() {
        val lines = """
            WifiScoringState true
            WifiPasspointState true
            WifiStateUser 10
            Dump of PasspointManager
            mEnabled: true
            PasspointManager - Providers Begin ---
            ProviderId: 0
            Configuration Begin ---
            HomeSP Begin ---
            FQDN: provider.example
            HomeSP End ---
            Credential Begin ---
            Realm: private.example
            Credential End ---
            CarrierId:-1SubscriptionId:-1IsAutojoinEnabled:falsemIsMacRandomizationEnabled:trueConfiguration End ---
            WifiConfiguration Begin ---
            SSID: ignored
            WifiConfiguration End ---
            PasspointManager - Providers End ---
        """.trimIndent().lines()
        assertEquals(true, PasspointDump.enabled(lines))
        assertNull(PasspointDump.enabled(lines.map { it.replace("mEnabled: true", "mEnabled: false") }))
        assertNull(PasspointDump.enabled(listOf("ScanAlwaysAvailable true")))
        assertEquals(listOf("provider.example" to false), PasspointDump.providers(lines, 10))
        assertNull(PasspointDump.providers(lines, 0))
        assertNull(PasspointDump.providers(lines.dropLast(1), 10))
        assertEquals(emptyList(), PasspointDump.providers(listOf("WifiStateUser 0",
            "PasspointManager - Providers Begin ---", "PasspointManager - Providers End ---"), 0))
    }

    @Test
    fun `printing distinguishes components in one app and isolates profiles`() {
        val text = """
            PRINT MANAGER STATE (dumpsys print)
            {
              user_states=[
                {
                  user_id=0
                  print_spooler_state={
                  }
                }
                {
                  user_id=10
                  installed_services=[
                    {
                      component_name={
                        package_name=example.print
                        class_name=example.print.First
                      }
                    }
                    {
                      component_name={
                        package_name=example.print
                        class_name=example.print.Second
                      }
                    }
                  ]
                  disabled_services={
                    package_name=example.print
                    class_name=example.print.First
                  }
                  print_spooler_state={
                    package_name=private.app
                  }
                }
              ]
            }
        """.trimIndent()
        assertEquals(mapOf("example.print/example.print.First" to false, "example.print/example.print.Second" to true),
            PrintServicesDump.parse(text, 10))
        assertEquals(emptyMap(), PrintServicesDump.parse(text, 0))
        assertNull(PrintServicesDump.parse(text, 11))
        assertNull(PrintServicesDump.parse(text.replace("class_name=example.print.First", "class_name=???"), 10))
        assertNull(PrintServicesDump.parse(text.substringBefore("disabled_services"), 10))
    }
}
