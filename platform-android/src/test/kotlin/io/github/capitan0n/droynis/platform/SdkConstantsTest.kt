package io.github.capitan0n.droynis.platform

import android.app.admin.DevicePolicyManager
import android.provider.Settings
import io.github.capitan0n.droynis.checks.base.BluetoothCheck
import io.github.capitan0n.droynis.checks.base.DeveloperOptionsCheck
import io.github.capitan0n.droynis.checks.base.PasswordVisibilityCheck
import io.github.capitan0n.droynis.checks.base.ScreenTimeoutCheck
import io.github.capitan0n.droynis.checks.base.StayAwakeCheck
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
        assertEquals(Settings.ACTION_PRIVACY_SETTINGS, SettingsActions.PRIVACY)
        assertEquals(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS, SettingsActions.DEVELOPER_OPTIONS)
        assertEquals(Settings.ACTION_WIRELESS_SETTINGS, SettingsActions.NETWORK)
        assertEquals(Settings.ACTION_WIFI_SETTINGS, SettingsActions.WIFI)
        assertEquals(Settings.ACTION_VPN_SETTINGS, SettingsActions.VPN)
        assertEquals(Settings.ACTION_BLUETOOTH_SETTINGS, SettingsActions.BLUETOOTH)
        assertEquals(Settings.ACTION_NFC_SETTINGS, SettingsActions.NFC)
        assertEquals(Settings.ACTION_DISPLAY_SETTINGS, SettingsActions.DISPLAY)
        assertEquals(Settings.ACTION_ACCESSIBILITY_SETTINGS, SettingsActions.ACCESSIBILITY)
        assertEquals(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS, SettingsActions.APPS)
        assertEquals(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, SettingsActions.UNKNOWN_APP_SOURCES)
        assertEquals(Settings.ACTION_USAGE_ACCESS_SETTINGS, SettingsActions.USAGE_ACCESS)
        assertEquals(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS, SettingsActions.NOTIFICATION_ACCESS)
        assertEquals(Settings.ACTION_INPUT_METHOD_SETTINGS, SettingsActions.INPUT_METHODS)
        assertEquals(Settings.ACTION_DEVICE_INFO_SETTINGS, SettingsActions.DEVICE_INFO)
        assertEquals(Settings.ACTION_SETTINGS, SettingsActions.SETTINGS)
    }

    @Test
    fun settingKeysMatchTheSdk() {
        assertEquals(Settings.Global.ADB_ENABLED, UsbDebuggingCheck.ADB_ENABLED)
        assertEquals(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, DeveloperOptionsCheck.DEVELOPMENT_SETTINGS_ENABLED)
        assertEquals(Settings.Global.BLUETOOTH_ON, BluetoothCheck.BLUETOOTH_ON)
        assertEquals(Settings.Global.STAY_ON_WHILE_PLUGGED_IN, StayAwakeCheck.STAY_ON_WHILE_PLUGGED_IN)
        assertEquals(Settings.System.SCREEN_OFF_TIMEOUT, ScreenTimeoutCheck.SCREEN_OFF_TIMEOUT)
        assertEquals(Settings.System.TEXT_SHOW_PASSWORD, PasswordVisibilityCheck.TEXT_SHOW_PASSWORD)
    }
}
