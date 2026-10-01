package io.github.capitan0n.droynis.platform

import android.app.admin.DevicePolicyManager
import android.provider.Settings
import io.github.capitan0n.droynis.checks.base.UsbDebuggingCheck
import io.github.capitan0n.droynis.core.SettingsActions
import org.junit.Assert.assertEquals
import org.junit.Test

/** The JVM modules hard-code these SDK strings; they must match the real constants. */
class SdkConstantsTest {

    @Test
    fun settingsActionsMatchTheSdk() {
        assertEquals(DevicePolicyManager.ACTION_SET_NEW_PASSWORD, SettingsActions.SET_NEW_PASSWORD)
        assertEquals(Settings.ACTION_SECURITY_SETTINGS, SettingsActions.SECURITY)
        assertEquals(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS, SettingsActions.DEVELOPER_OPTIONS)
        assertEquals(Settings.ACTION_SETTINGS, SettingsActions.SETTINGS)
    }

    @Test
    fun settingKeysMatchTheSdk() {
        assertEquals(Settings.Global.ADB_ENABLED, UsbDebuggingCheck.ADB_ENABLED)
    }
}
