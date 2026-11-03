package io.github.capitan0n.droynis.core

/**
 * Literal values of Android intent actions used in [Remediation.settingsActions]. Kept as strings so
 * this module needs no Android SDK; :platform-android tests that the public ones match the SDK.
 * A few Settings screens have no action at all: those are explicit activities, written
 * `package/.Class` ([isComponent]).
 */
object SettingsActions {
    /** `DevicePolicyManager.ACTION_SET_NEW_PASSWORD`: starts the screen lock setup flow. */
    const val SET_NEW_PASSWORD = "android.app.action.SET_NEW_PASSWORD"

    /** `Settings.ACTION_SECURITY_SETTINGS` */
    const val SECURITY = "android.settings.SECURITY_SETTINGS"

    /**
     * `Settings.ACTION_PRIVACY_SETTINGS`: Privacy, with Permission manager, from Android 10. Android 8
     * and 9 open Backup with it, so [minSdk] skips it there.
     */
    const val PRIVACY = "android.settings.PRIVACY_SETTINGS"

    /**
     * Hidden from the public SDK (`Settings.ACTION_PRIVACY_CONTROLS`): Privacy controls, with the
     * camera and microphone switches and "Show clipboard access" (Android 13+). The AOSP Settings app
     * exports it.
     */
    const val PRIVACY_CONTROLS = "android.settings.PRIVACY_CONTROLS"

    /** `Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS` */
    const val DEVELOPER_OPTIONS = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"

    /** `Settings.ACTION_WIRELESS_SETTINGS`: Network & internet, where Private DNS lives. */
    const val NETWORK = "android.settings.WIRELESS_SETTINGS"

    /** `Settings.ACTION_WIFI_SETTINGS` */
    const val WIFI = "android.settings.WIFI_SETTINGS"

    /**
     * Not in the public SDK (`Settings.ACTION_WIFI_SAVED_NETWORK_SETTINGS`): the Saved networks
     * list, where each network can be forgotten or kept from joining by itself. The AOSP Settings app
     * exports it (Android 9+).
     */
    const val WIFI_SAVED_NETWORKS = "android.settings.WIFI_SAVED_NETWORK_SETTINGS"

    /**
     * Hidden from the public SDK (`Settings.ACTION_WIFI_TETHER_SETTING`): the Wi-Fi hotspot screen,
     * with its security, password and "Turn off hotspot automatically". The AOSP Settings app exports it.
     */
    const val WIFI_HOTSPOT = "com.android.settings.WIFI_TETHER_SETTINGS"

    /** System API (`Settings.ACTION_TETHER_SETTINGS`): Hotspot & tethering. The AOSP Settings app exports it. */
    const val TETHERING = "android.settings.TETHER_SETTINGS"

    /** `Settings.ACTION_DATA_ROAMING_SETTINGS`: the Mobile network page, with network mode and Allow 2G. */
    const val MOBILE_NETWORK = "android.settings.DATA_ROAMING_SETTINGS"

    /**
     * Not in the SDK: Mobile network security, with Require encryption and Network notifications
     * (Android 15+). The AOSP Settings app exports it.
     */
    const val CELLULAR_NETWORK_SECURITY = "android.settings.CELLULAR_NETWORK_SECURITY"

    /** `Settings.ACTION_APN_SETTINGS`: Access point names, where a mobile data proxy is set. */
    const val APN = "android.settings.APN_SETTINGS"

    /** `Settings.ACTION_VPN_SETTINGS` */
    const val VPN = "android.settings.VPN_SETTINGS"

    /** `Settings.ACTION_BLUETOOTH_SETTINGS` */
    const val BLUETOOTH = "android.settings.BLUETOOTH_SETTINGS"

    /** `Settings.ACTION_LOCATION_SOURCE_SETTINGS`: Location, including Wi-Fi and Bluetooth scanning. */
    const val LOCATION = "android.settings.LOCATION_SOURCE_SETTINGS"

    /**
     * Not in the public SDK (`Settings.ACTION_LOCATION_SCANNING_SETTINGS`): Wi-Fi and Bluetooth
     * scanning (Location services on recent releases). The AOSP Settings app exports it (Android 9+).
     */
    const val LOCATION_SCANNING = "android.settings.LOCATION_SCANNING_SETTINGS"

    /** `Settings.ACTION_NFC_SETTINGS` */
    const val NFC = "android.settings.NFC_SETTINGS"

    /** `Settings.ACTION_DISPLAY_SETTINGS`: screen timeout. */
    const val DISPLAY = "android.settings.DISPLAY_SETTINGS"

    /**
     * Not in the public SDK: the Screen timeout picker itself (recent releases). The AOSP
     * Settings app exports it; [DISPLAY] follows as the fallback.
     */
    const val SCREEN_TIMEOUT = "android.settings.SCREEN_TIMEOUT_SETTINGS"

    /**
     * Not in the public SDK (`Settings.ACTION_FACE_SETTINGS`, Android 10+): Face Unlock, after the
     * PIN. AOSP's screen closes at once on a phone without face hardware, so [route] skips it there.
     */
    const val FACE = "android.settings.FACE_SETTINGS"

    /**
     * No action opens Device admin apps: this is AOSP's explicit activity, an alias the Settings app
     * keeps under this name for old home screen shortcuts.
     */
    const val DEVICE_ADMINS = "com.android.settings/.DeviceAdminSettings"

    /**
     * No action opens Languages & input, where the autofill service picker lives up to Android 11:
     * this is AOSP's explicit activity. Android 12 moved the picker to [ACCOUNTS].
     */
    const val LANGUAGE_AND_INPUT = "com.android.settings/.Settings\$LanguageAndInputSettingsActivity"

    /**
     * Hidden from the public SDK (`Settings.ACTION_LOCKSCREEN_SETTINGS`): Lock screen, with "Show
     * wallet", "Show device controls" and the switch that lets them work while locked (Android 13+).
     * The AOSP Settings app exports it.
     */
    const val LOCK_SCREEN = "android.settings.LOCK_SCREEN_SETTINGS"

    /** `Settings.ACTION_ACCESSIBILITY_SETTINGS` */
    const val ACCESSIBILITY = "android.settings.ACCESSIBILITY_SETTINGS"

    /** `Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS`: the installed apps list. */
    const val APPS = "android.settings.MANAGE_APPLICATIONS_SETTINGS"

    /**
     * `Settings.ACTION_APPLICATION_DETAILS_SETTINGS`: one app's App info, with its permissions,
     * battery use and Uninstall. Needs a `package:` URI; the UI's last resort for a named app.
     */
    const val APP_DETAILS = "android.settings.APPLICATION_DETAILS_SETTINGS"

    /** `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` */
    const val UNKNOWN_APP_SOURCES = "android.settings.MANAGE_UNKNOWN_APP_SOURCES"

    /** `Settings.ACTION_USAGE_ACCESS_SETTINGS` */
    const val USAGE_ACCESS = "android.settings.USAGE_ACCESS_SETTINGS"

    /** `Settings.ACTION_MANAGE_OVERLAY_PERMISSION`: Display over other apps. */
    const val OVERLAY = "android.settings.action.MANAGE_OVERLAY_PERMISSION"

    /** `Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION`: All files access, Android 11+. */
    const val ALL_FILES_ACCESS = "android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION"

    /**
     * `Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION`: one app's All files access switch,
     * Android 11+. Needs a `package:` URI.
     */
    const val APP_ALL_FILES_ACCESS = "android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION"

    /** `Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS`: the list of apps by battery optimization. */
    const val BATTERY_OPTIMIZATION = "android.settings.IGNORE_BATTERY_OPTIMIZATION_SETTINGS"

    /** `Settings.ACTION_MANAGE_WRITE_SETTINGS`: Modify system settings. */
    const val WRITE_SETTINGS = "android.settings.action.MANAGE_WRITE_SETTINGS"

    /** `Settings.ACTION_REQUEST_MANAGE_MEDIA`: Media management apps, Android 12+. */
    const val MANAGE_MEDIA = "android.settings.REQUEST_MANAGE_MEDIA"

    /** `Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS` */
    const val NOTIFICATION_ACCESS = "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"

    /** `Settings.ACTION_INPUT_METHOD_SETTINGS`: on-screen keyboards. */
    const val INPUT_METHODS = "android.settings.INPUT_METHOD_SETTINGS"

    /**
     * `Settings.ACTION_SYNC_SETTINGS`: Passwords, passkeys & accounts, which also holds the autofill
     * service picker from Android 12 on; before that it opens Accounts only, so [minSdk] skips it
     * there. `ACTION_CREDENTIAL_PROVIDER` needs a `package:` URI.
     */
    const val ACCOUNTS = "android.settings.SYNC_SETTINGS"

    /**
     * `Settings.ACTION_VOICE_INPUT_SETTINGS`: Assist & voice input. Android 17 Settings drops it behind
     * a flag, so [DEFAULT_APPS] follows as the fallback.
     */
    const val VOICE_INPUT = "android.settings.VOICE_INPUT_SETTINGS"

    /** `Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS`: Default apps, including the digital assistant. */
    const val DEFAULT_APPS = "android.settings.MANAGE_DEFAULT_APPS_SETTINGS"

    /**
     * Hidden from the public SDK (`Settings.ACTION_LOCKSCREEN_NOTIFICATIONS_SETTINGS`, recent releases
     * only); listed first and skipped where the Settings app does not export it.
     */
    const val LOCK_SCREEN_NOTIFICATIONS = "android.settings.LOCK_SCREEN_NOTIFICATIONS_SETTINGS"

    /** Hidden from the public SDK (`Settings.ACTION_NOTIFICATION_SETTINGS`); exported by the Settings app. */
    const val NOTIFICATIONS = "android.settings.NOTIFICATION_SETTINGS"

    /**
     * Hidden from the public SDK (`Settings.ACTION_NOTIFICATION_HISTORY`, Android 11+): the
     * Notification history screen, with its on/off switch. Exported by the AOSP Settings app.
     */
    const val NOTIFICATION_HISTORY = "android.settings.NOTIFICATION_HISTORY"

    /** Not in the SDK: Trusted credentials, on its System tab. The AOSP Settings app exports it. */
    const val TRUSTED_CREDENTIALS = "com.android.settings.TRUSTED_CREDENTIALS"

    /**
     * Not in the SDK: the User tab of Trusted credentials. The AOSP Settings app exports it, and
     * Android's own "Network may be monitored" notification opens it.
     */
    const val TRUSTED_CREDENTIALS_USER = "com.android.settings.TRUSTED_CREDENTIALS_USER"

    /** `Settings.ACTION_DEVICE_INFO_SETTINGS`: About phone. */
    const val DEVICE_INFO = "android.settings.DEVICE_INFO_SETTINGS"

    /** `Settings.ACTION_SETTINGS`: the fallback when nothing more specific opens. */
    const val SETTINGS = "android.settings.SETTINGS"

    /** The key of Build number in About phone ([DEVICE_INFO]): tapped seven times, it turns Developer options on. */
    const val BUILD_NUMBER_KEY = "build_number"

    /**
     * `SettingsActivity.EXTRA_FRAGMENT_ARG_KEY`: the key of the preference to scroll to and highlight.
     * AOSP reads it from [EXTRA_SHOW_FRAGMENT_ARGUMENTS], and from the intent itself on recent releases,
     * so the UI sends both.
     */
    const val EXTRA_FRAGMENT_ARG_KEY = ":settings:fragment_args_key"

    /** `SettingsActivity.EXTRA_SHOW_FRAGMENT_ARGUMENTS`: the bundle a Settings screen gets its arguments from. */
    const val EXTRA_SHOW_FRAGMENT_ARGUMENTS = ":settings:show_fragment_args"

    /** Actions that exist on older releases but open the wrong screen there, with the first good API level. */
    private val MIN_SDK = mapOf(PRIVACY to 29, ACCOUNTS to 31)

    /** Screens that newer releases still have, but without what the constant describes, with the last good API level. */
    private val MAX_SDK = mapOf(LANGUAGE_AND_INPUT to 30)

    /** Screens that close at once without a hardware feature, with that `PackageManager` feature. */
    private val FEATURES = mapOf(FACE to "android.hardware.biometrics.face")

    /** The API level from which [action] opens the screen its constant describes. */
    fun minSdk(action: String): Int = MIN_SDK[action] ?: 0

    /** The last API level on which [action] opens the screen its constant describes. */
    fun maxSdk(action: String): Int = MAX_SDK[action] ?: Int.MAX_VALUE

    /** Whether [action] opens the screen its constant describes on API level [sdkInt]. */
    fun opensOn(action: String, sdkInt: Int): Boolean = sdkInt in minSdk(action)..maxSdk(action)

    /** An explicit activity (`package/.Class`) rather than an intent action; actions never hold a slash. */
    fun isComponent(target: String): Boolean = '/' in target

    /**
     * What the UI tries for one "Open settings" tap: the [actions] this phone's release has, in order,
     * then the main Settings screen.
     *
     * Developer options close again at once while they are off ("Please enable developer options
     * first"), so with [developerOptionsOn] false, About phone opens in their place with Build number
     * highlighted, and [SettingsRoute.developerOptionsOff] tells the UI to say why.
     *
     * @param highlightKey [Remediation.highlightKey], sent to each of [actions].
     * @param hasFeature whether the phone has a `PackageManager` system feature.
     */
    fun route(
        actions: List<String>,
        sdkInt: Int,
        highlightKey: String? = null,
        developerOptionsOn: Boolean? = null,
        hasFeature: (String) -> Boolean = { true },
    ): SettingsRoute {
        val usable = actions.filter { opensOn(it, sdkInt) && FEATURES[it]?.let(hasFeature) != false }
        val developerOptionsOff = developerOptionsOn == false && DEVELOPER_OPTIONS in usable
        val targets = usable.map {
            if (developerOptionsOff && it == DEVELOPER_OPTIONS) {
                SettingsTarget(DEVICE_INFO, BUILD_NUMBER_KEY)
            } else {
                SettingsTarget(it, highlightKey)
            }
        }
        return SettingsRoute((targets + SettingsTarget(SETTINGS)).distinctBy { it.target }, developerOptionsOff)
    }
}

/** One Settings screen to try: an intent action or an explicit activity, and the switch to highlight on it. */
data class SettingsTarget(val target: String, val highlightKey: String? = null) {
    val isComponent: Boolean get() = SettingsActions.isComponent(target)
}

/**
 * The screens to try in order, ending with the main Settings screen. [developerOptionsOff]: About
 * phone stands in for Developer options, which are off.
 */
data class SettingsRoute(val targets: List<SettingsTarget>, val developerOptionsOff: Boolean = false)
