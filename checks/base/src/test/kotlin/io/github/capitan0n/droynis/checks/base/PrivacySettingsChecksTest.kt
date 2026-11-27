package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Status
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class PrivacySettingsChecksTest {
    @Test
    fun `pinning only scores when enabled and uses the secure lock default`() = runTest {
        suspend fun status(pinning: String?, exit: String?, secure: Reading<Boolean>) = AppPinningCheck(
            FakeSettings(system = mapOf("lock_to_app_enabled" to value(pinning)),
                secure = mapOf("lock_to_app_exit_locked" to value(exit))),
            FakeKeyguard(secure),
        ).status()

        assertEquals(Status.UNSUPPORTED, status(null, null, value(false)))
        assertEquals(Status.UNSUPPORTED, status("0", "0", value(false)))
        assertEquals(Status.FAIL, status("1", "0", value(true)))
        assertEquals(Status.PASS, status("1", "1", value(true)))
        assertEquals(Status.PASS, status("1", null, value(true)))
        assertEquals(Status.FAIL, status("1", null, value(false)))
        assertEquals(Status.UNKNOWN, status("1", null, unavailable()))
    }

    @Test
    fun `lock screen user creation honors restrictions and the user switcher`() = runTest {
        suspend fun status(allowed: Reading<Boolean>, add: String?, switcher: String? = "1") = LockScreenUsersCheck(
            FakeSettings(global = mapOf("add_users_when_locked" to value(add), "user_switcher_enabled" to value(switcher))),
        ) { allowed }.status()

        assertEquals(Status.FAIL, status(value(true), "1"))
        assertEquals(Status.PASS, status(value(true), "0"))
        assertEquals(Status.UNKNOWN, status(value(true), null))
        assertEquals(Status.UNKNOWN, status(unavailable(), "0"))
        assertEquals(Status.UNSUPPORTED, status(value(false), "1"))
        assertEquals(Status.UNSUPPORTED, status(value(true), "1", switcher = "0"))
    }

    @Test
    fun `spell checking off ignores a saved component and on requires a valid service`() = runTest {
        val saved = "com.google.android.inputmethod.latin/.SpellChecker"
        val provider = InstalledApp(saved.substringBefore('/'), isSystem = true, isDebuggable = false, installer = null, targetSdk = 35)
        fun check(enabled: String?, available: () -> Reading<Boolean>, app: InstalledApp = provider) = SpellCheckerCheck(
            FakeSettings(secure = mapOf("spell_checker_enabled" to value(enabled), "selected_spell_checker" to value(saved))),
            FakePackages(value(listOf(app)), mapOf(app.packageName to "Gboard")),
        ) { component ->
            assertEquals(saved, component)
            available()
        }

        assertEquals("Android spell checking is off", check("0", { error("disabled switch wins") }).outcome().summary)
        assertEquals("Spell checker: Gboard (built-in)", check(null, { value(true) }).outcome().summary)
        assertEquals(Status.UNKNOWN, check("1", { value(false) }).status())
        assertEquals(Status.UNKNOWN, check("1", { unavailable() }).status())

        val thirdParty = check("1", { value(true) }, provider.copy(isSystem = false))
        assertEquals(Status.PASS, thirdParty.status())
        assertEquals(Severity.INFO, thirdParty.spec.severity)
    }

    @Test
    fun `backup switch off is informational and missing data stays unknown`() = runTest {
        suspend fun check(setting: Reading<String?>) =
            BackupStatusCheck(FakeSettings(secure = mapOf("backup_enabled" to setting))).outcome()

        val off = check(value("0"))
        assertEquals(Status.PASS, off.status)
        assertEquals("Android backup is off", off.summary)
        assertEquals("Android backup is on", check(value("1")).summary)
        assertEquals(Status.UNKNOWN, check(value(null)).status)
        assertEquals(Status.UNKNOWN, check(unavailable()).status)
    }

    @Test
    fun `Play services presence never proves that theft protection is enabled`() = runTest {
        val play = InstalledApp("com.google.android.gms", isSystem = true, isDebuggable = false, installer = null, targetSdk = 35)
        assertEquals(Status.UNKNOWN, TheftProtectionCheck(FakePackages(value(listOf(play)))).status())
        assertEquals(Status.UNSUPPORTED, TheftProtectionCheck(FakePackages(value(listOf(play.copy(isEnabled = false))))).status())
        assertEquals(Status.UNSUPPORTED, TheftProtectionCheck(FakePackages()).status())
    }
}
