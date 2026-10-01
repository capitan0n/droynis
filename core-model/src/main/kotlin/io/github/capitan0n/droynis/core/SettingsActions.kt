package io.github.capitan0n.droynis.core

/**
 * Literal values of public Android intent actions used in [Remediation.settingsActions].
 * Kept as strings so this module needs no Android SDK; :platform-android tests that they match.
 */
object SettingsActions {
    /** `DevicePolicyManager.ACTION_SET_NEW_PASSWORD`: starts the screen lock setup flow. */
    const val SET_NEW_PASSWORD = "android.app.action.SET_NEW_PASSWORD"

    /** `Settings.ACTION_SECURITY_SETTINGS` */
    const val SECURITY = "android.settings.SECURITY_SETTINGS"

    /** `Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS` */
    const val DEVELOPER_OPTIONS = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"

    /** `Settings.ACTION_SETTINGS`: the fallback when nothing more specific opens. */
    const val SETTINGS = "android.settings.SETTINGS"
}
