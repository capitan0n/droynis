package io.github.capitan0n.droynis.core

/**
 * Literal values of Android intent actions used in [Remediation.settingsActions]. Kept as strings so
 * this module needs no Android SDK; :platform-android tests that the public ones match the SDK.
 */
object SettingsActions {
    /** `DevicePolicyManager.ACTION_SET_NEW_PASSWORD`: starts the screen lock setup flow. */
    const val SET_NEW_PASSWORD = "android.app.action.SET_NEW_PASSWORD"

    /** `Settings.ACTION_SECURITY_SETTINGS` */
    const val SECURITY = "android.settings.SECURITY_SETTINGS"

    /** `Settings.ACTION_PRIVACY_SETTINGS` */
    const val PRIVACY = "android.settings.PRIVACY_SETTINGS"

    /** `Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS` */
    const val DEVELOPER_OPTIONS = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"

    /** `Settings.ACTION_WIRELESS_SETTINGS`: Network & internet, where Private DNS lives. */
    const val NETWORK = "android.settings.WIRELESS_SETTINGS"

    /** `Settings.ACTION_WIFI_SETTINGS` */
    const val WIFI = "android.settings.WIFI_SETTINGS"

    /** `Settings.ACTION_VPN_SETTINGS` */
    const val VPN = "android.settings.VPN_SETTINGS"

    /** `Settings.ACTION_BLUETOOTH_SETTINGS` */
    const val BLUETOOTH = "android.settings.BLUETOOTH_SETTINGS"

    /** `Settings.ACTION_LOCATION_SOURCE_SETTINGS`: Location, including Wi-Fi and Bluetooth scanning. */
    const val LOCATION = "android.settings.LOCATION_SOURCE_SETTINGS"

    /** `Settings.ACTION_NFC_SETTINGS` */
    const val NFC = "android.settings.NFC_SETTINGS"

    /** `Settings.ACTION_DISPLAY_SETTINGS`: screen timeout. */
    const val DISPLAY = "android.settings.DISPLAY_SETTINGS"

    /** `Settings.ACTION_ACCESSIBILITY_SETTINGS` */
    const val ACCESSIBILITY = "android.settings.ACCESSIBILITY_SETTINGS"

    /** `Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS`: the installed apps list. */
    const val APPS = "android.settings.MANAGE_APPLICATIONS_SETTINGS"

    /** `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` */
    const val UNKNOWN_APP_SOURCES = "android.settings.MANAGE_UNKNOWN_APP_SOURCES"

    /** `Settings.ACTION_USAGE_ACCESS_SETTINGS` */
    const val USAGE_ACCESS = "android.settings.USAGE_ACCESS_SETTINGS"

    /** `Settings.ACTION_MANAGE_OVERLAY_PERMISSION`: Display over other apps. */
    const val OVERLAY = "android.settings.action.MANAGE_OVERLAY_PERMISSION"

    /** `Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION`: All files access, Android 11+. */
    const val ALL_FILES_ACCESS = "android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION"

    /** `Settings.ACTION_MANAGE_WRITE_SETTINGS`: Modify system settings. */
    const val WRITE_SETTINGS = "android.settings.action.MANAGE_WRITE_SETTINGS"

    /** `Settings.ACTION_REQUEST_MANAGE_MEDIA`: Media management apps, Android 12+. */
    const val MANAGE_MEDIA = "android.settings.REQUEST_MANAGE_MEDIA"

    /** `Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS` */
    const val NOTIFICATION_ACCESS = "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"

    /** `Settings.ACTION_INPUT_METHOD_SETTINGS`: on-screen keyboards. */
    const val INPUT_METHODS = "android.settings.INPUT_METHOD_SETTINGS"

    /**
     * Hidden from the public SDK (`Settings.ACTION_LOCKSCREEN_NOTIFICATIONS_SETTINGS`, recent releases
     * only); listed first and skipped where the Settings app does not export it.
     */
    const val LOCK_SCREEN_NOTIFICATIONS = "android.settings.LOCK_SCREEN_NOTIFICATIONS_SETTINGS"

    /** Hidden from the public SDK (`Settings.ACTION_NOTIFICATION_SETTINGS`); exported by the Settings app. */
    const val NOTIFICATIONS = "android.settings.NOTIFICATION_SETTINGS"

    /** `Settings.ACTION_DEVICE_INFO_SETTINGS`: About phone. */
    const val DEVICE_INFO = "android.settings.DEVICE_INFO_SETTINGS"

    /** `Settings.ACTION_SETTINGS`: the fallback when nothing more specific opens. */
    const val SETTINGS = "android.settings.SETTINGS"
}
