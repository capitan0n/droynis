package io.github.capitan0n.droynis.checks.adb

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
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

class SmartLockCheckTest {

    private val source = Source("dumpsys trust", Grant.SHIZUKU)
    private val context = ScanContext(ZonedDateTime.of(2026, 10, 6, 12, 0, 0, 0, ZoneOffset.UTC), sdkInt = 37)

    private fun check(dump: Reading<String>) = SmartLockCheck(
        dumpsys = object : Dumpsys {
            override fun dump(service: String, vararg args: String) = dump
        },
        packages = object : PackageInventory {
            override fun installedApps(): Reading<List<InstalledApp>> = Reading.Value(emptyList(), source)
            override fun label(packageName: String) = if (packageName == "com.google.android.gms") "Google Play services" else packageName
        },
    )

    @Test
    fun `needs dump, so the adb tier or anything above it`() {
        assertEquals(setOf(Grant.DUMP), check(Reading.Value("", source)).spec.requires)
        assertEquals(Tier.ADB, check(Reading.Value("", source)).spec.requiredTier)
    }

    @Test
    fun `a trust agent that manages trust fails, naming the agent but never the user`() = runTest {
        val outcome = check(Reading.Value(dump(managed = true, managingTrust = true, trusted = true), source)).run(context)

        assertEquals(Status.FAIL, outcome.status)
        assertEquals("Google Play services can keep the phone unlocked", outcome.summary)
        val agent = outcome.evidence.single { it.label == "Trust agent" }
        assertEquals("keeping the phone unlocked now", agent.note)
        assertFalse(outcome.evidence.any { "Alexandros" in it.value.orEmpty() || "Home" in it.note.orEmpty() })
    }

    @Test
    fun `an enabled agent that is not set up passes`() = runTest {
        val outcome = check(Reading.Value(dump(managed = false, managingTrust = false, trusted = false), source)).run(context)

        assertEquals(Status.PASS, outcome.status)
        assertEquals("enabled, not set up", outcome.evidence.single { it.label == "Trust agent" }.note)
    }

    @Test
    fun `active unlock alone also keeps the phone unlocked`() = runTest {
        val text = dump(managed = false, managingTrust = false, trusted = false).replace("isActiveUnlockRunning=0", "isActiveUnlockRunning=1")
        assertEquals(Status.FAIL, check(Reading.Value(text, source)).run(context).status)
    }

    @Test
    fun `older releases without trustState or active unlock still parse`() {
        val android11 = """
            Trust manager state:
             User "Owner" (id=0, flags=0x13) (current): trusted=0, trustManaged=1, deviceLocked=1, strongAuthRequired=0x0
               Enabled agents:
                com.google.android.gms/.auth.trustagent.GoogleTrustAgent
                 bound=1, connected=1, managingTrust=1, trusted=0
               Events:
        """.trimIndent()
        val parsed = assertIs<TrustDump.Result.Parsed>(TrustDump.parse(android11))
        assertTrue(parsed.trustManaged)
        assertEquals(null, parsed.activeUnlock)
        assertEquals(1, parsed.agents.size)
    }

    @Test
    fun `only the current user counts, and odd output is unknown`() = runTest {
        val twoUsers = dump(managed = false, managingTrust = false, trusted = false) +
            "\n User \"Work\" (id=10, flags=0x30): trustState=UNTRUSTED, trustManaged=1, deviceLocked=1\n"
        assertEquals(Status.PASS, check(Reading.Value(twoUsers, source)).run(context).status)

        assertEquals(Status.UNKNOWN, check(Reading.Value("disabled because the system is in safe mode.", source)).run(context).status)
        assertEquals(Status.UNKNOWN, check(Reading.Value("Trust manager state:\n", source)).run(context).status)
        assertEquals(Status.UNKNOWN, check(Reading.Unavailable("Permission Denial", source)).run(context).status)
    }

    private fun dump(managed: Boolean, managingTrust: Boolean, trusted: Boolean): String {
        fun b(value: Boolean) = if (value) "1" else "0"
        return """
            Trust manager state:
             User "Alexandros" (id=0, flags=0xc13) (current): trustState=TRUSTED, trustManaged=${b(managed)}, deviceLocked=0, isActiveUnlockRunning=0, strongAuthRequired=0x0
               Enabled agents:
                com.google.android.gms/.auth.trustagent.GoogleTrustAgent
                 bound=1, connected=1, managingTrust=${b(managingTrust)}, trusted=${b(trusted)}
                  message="Kept unlocked at Home"
               Events:
                #0 12:00:00.000 TrustAgentWrapper: agent connected
        """.trimIndent()
    }
}
