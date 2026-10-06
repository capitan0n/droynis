package io.github.capitan0n.droynis.checks.adb

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AppOpModesTest {

    private fun allowed(text: String, vararg ops: String) =
        assertIs<AppOpModes.Result.Parsed>(AppOpModes.allowed(text, ops.toSet()))

    @Test
    fun `package modes decide when the uid has none`() {
        val result = allowed(SAMPLE, "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES")

        assertEquals(5, result.packages)
        assertEquals(
            listOf(
                OpGrant("org.example.bubbles", "u0a130", "SYSTEM_ALERT_WINDOW", "allow"),
                OpGrant("org.example.browser", "u0a131", "REQUEST_INSTALL_PACKAGES", "allow"),
            ),
            result.grants,
        )
    }

    @Test
    fun `a uid mode decides for every package of the uid, over their own modes`() {
        val files = allowed(SAMPLE, "MANAGE_EXTERNAL_STORAGE").grants
        assertEquals(
            listOf(OpGrant("org.example.files", "u0a132", "MANAGE_EXTERNAL_STORAGE", "allow", uidWide = true)),
            files,
        )

        // u0a131 denies the overlay for the whole uid, so its package's own "allow" does not count.
        val overlay = allowed(SAMPLE, "SYSTEM_ALERT_WINDOW").grants
        assertEquals(listOf("org.example.bubbles"), overlay.map { it.packageName })
    }

    @Test
    fun `a uid-wide grant without packages keeps the uid`() {
        val text = "AppOps Uid Op State\n  Uid u0a140:\n    state=cch\n      GET_USAGE_STATS: mode=allow\n" +
            "  Uid u0a141:\n    Package org.example.other:\n      WAKE_LOCK (allow):\n"

        val grant = allowed(text, "GET_USAGE_STATS").grants.single()
        assertNull(grant.packageName)
        assertEquals("u0a140", grant.uid)
    }

    @Test
    fun `foreground counts as allowed and a switch op decides for the op it switches`() {
        val text = "AppOps Uid Op State\n  Uid u0a150:\n    Package org.example.a:\n" +
            "      SYSTEM_ALERT_WINDOW (foreground):\n" +
            "  Uid u0a151:\n    Package org.example.b:\n" +
            "      REQUEST_INSTALL_PACKAGES (ignore / switch REQUEST_INSTALL_PACKAGES=allow):\n"

        val grants = allowed(text, "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES").grants
        assertEquals(listOf("foreground", "allow"), grants.map { it.mode })
    }

    @Test
    fun `a requested op in an unknown shape fails the parse`() {
        val changed = SAMPLE.replace("SYSTEM_ALERT_WINDOW (allow):", "SYSTEM_ALERT_WINDOW (allow): time=+1h ago")
        assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed(changed, setOf("SYSTEM_ALERT_WINDOW")))

        val unknownMode = SAMPLE.replace("MANAGE_EXTERNAL_STORAGE: mode=allow", "MANAGE_EXTERNAL_STORAGE: mode=mode=7")
        assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed(unknownMode, setOf("MANAGE_EXTERNAL_STORAGE")))
    }

    @Test
    fun `odd lines about other ops do not matter`() {
        val changed = SAMPLE.replace("WAKE_LOCK (allow):", "WAKE_LOCK (mode=9):")

        allowed(changed, "SYSTEM_ALERT_WINDOW")
        assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed(changed, setOf("WAKE_LOCK")))
    }

    @Test
    fun `android 11 and older have no section header, and the first uid counts too`() {
        val android11 = """
            Current AppOps Service state:
              Settings:
                top_state_settle_time=+30s0ms
              Uid 0:
                state=pers
                Package root:
                  GET_USAGE_STATS (allow):
                Package com.android.shell:
                  SYSTEM_ALERT_WINDOW (allow):
              Uid u0a130:
                state=cch
                Package org.example.bubbles:
                  SYSTEM_ALERT_WINDOW (allow):
        """.trimIndent()

        val result = allowed(android11, "SYSTEM_ALERT_WINDOW", "GET_USAGE_STATS")
        assertEquals(3, result.packages)
        assertEquals(setOf("root", "com.android.shell", "org.example.bubbles"), result.grants.map { it.packageName }.toSet())
    }

    @Test
    fun `a failure quotes the first unexpected line`() {
        val changed = SAMPLE.replace("SYSTEM_ALERT_WINDOW (allow):", "SYSTEM_ALERT_WINDOW (allow): time=+1h ago")
        val failed = assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed(changed, setOf("SYSTEM_ALERT_WINDOW")))
        assertTrue(failed.reason.endsWith("\"SYSTEM_ALERT_WINDOW (allow): time=+1h ago\""), failed.reason)
    }

    @Test
    fun `the per-app part ends at the next unindented line`() {
        val text = SAMPLE + "\nAppOps Historical Service State:\n  Package org.example.history:\n" +
            "    SYSTEM_ALERT_WINDOW (allow):\n"

        assertEquals(listOf("org.example.bubbles"), allowed(text, "SYSTEM_ALERT_WINDOW").grants.map { it.packageName })
    }

    @Test
    fun `output without per-app data fails`() {
        assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed("", setOf("SYSTEM_ALERT_WINDOW")))
        assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed("Permission Denial: can't dump appops", setOf("GET_USAGE_STATS")))
        assertIs<AppOpModes.Result.Failed>(AppOpModes.allowed("AppOps Uid Op State\n", setOf("GET_USAGE_STATS")))
    }

    @Test
    fun `app uids follow UserHandle formatUid`() {
        assertEquals(10123, AppOpModes.uidOf("u0a123"))
        assertEquals(1_010_005, AppOpModes.uidOf("u10a5"))
        assertNull(AppOpModes.uidOf("1000"))
        assertNull(AppOpModes.uidOf("u0i3"))
    }

    companion object {
        /** Shaped like Android 17 output, `AppOpsService.dumpImpl`. */
        val SAMPLE = """
            AppOps Uid Op State
              Uid 1000:
                state=pers
                capability=LCMNU
                appWidgetVisible=false
                Package android:
                  WAKE_LOCK (allow):
                    null=[
                      Access: [pers-s] 2026-10-05 11:59:59.000 (-1s2ms)
                    ]
              Uid u0a130:
                state=cch
                Package org.example.bubbles:
                  SYSTEM_ALERT_WINDOW (allow):
                  REQUEST_INSTALL_PACKAGES (ignore):
              Uid u0a131:
                state=cch
                  SYSTEM_ALERT_WINDOW: mode=ignore
                Package org.example.browser:
                  SYSTEM_ALERT_WINDOW (allow):
                  REQUEST_INSTALL_PACKAGES (allow):
                    null=[
                      Access: [top-s] 2026-10-05 11:00:00.000 (-1h0m0s0ms)
                    ]
              Uid u0a132:
                state=cch
                  MANAGE_EXTERNAL_STORAGE: mode=allow
                Package org.example.files:
                  MANAGE_EXTERNAL_STORAGE (default):
              Uid u0a133:
                state=top
                Package org.example.notes:
                  SYSTEM_ALERT_WINDOW (default):
                  GET_USAGE_STATS (deny):
        """.trimIndent()
    }
}
