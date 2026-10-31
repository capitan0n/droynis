package io.github.capitan0n.droynis

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
import android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
import android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
import android.content.pm.PackageManager.DONT_KILL_APP
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes

/**
 * The launcher icons the user can pick (⋮ › App icon). Each is an activity-alias in the manifest;
 * exactly one is enabled at a time. [DEFAULT] is the one the manifest enables, so a new install,
 * and every reset to it, shows the original icon.
 */
enum class AppIcon(
    /** The activity-alias's name, after the package. */
    private val alias: String,
    @StringRes val labelRes: Int,
    /** The icon's foreground layer, for the picker; every icon shares ic_launcher_background. */
    @DrawableRes val foregroundRes: Int,
) {
    DEFAULT("MainActivity", R.string.app_icon_default, R.drawable.ic_launcher_foreground),
    SOMBRERO("IconSombrero", R.string.app_icon_sombrero, R.drawable.ic_launcher_foreground_sombrero),
    GLASSES("IconGlasses", R.string.app_icon_glasses, R.drawable.ic_launcher_foreground_glasses),
    EYEPATCH("IconEyepatch", R.string.app_icon_eyepatch, R.drawable.ic_launcher_foreground_eyepatch),
    COWBOY("IconCowboy", R.string.app_icon_cowboy, R.drawable.ic_launcher_foreground_cowboy),
    BLONDE("IconBlonde", R.string.app_icon_blonde, R.drawable.ic_launcher_foreground_blonde),
    ;

    // The manifest's names are relative to the namespace, which the activity's kept name carries.
    private fun component(context: Context) =
        ComponentName(context, DroynisActivity::class.java.name.substringBeforeLast('.') + "." + alias)

    companion object {
        /** The icon the launcher shows now; [DEFAULT] unless another one was picked. */
        fun current(context: Context): AppIcon {
            val pm = context.packageManager
            return entries.firstOrNull {
                it != DEFAULT && pm.getComponentEnabledSetting(it.component(context)) == COMPONENT_ENABLED_STATE_ENABLED
            } ?: DEFAULT
        }

        /**
         * Makes [icon] the launcher's entry; false if Android refused. The new entry is enabled before
         * the old one is disabled, so the app always has one. Every alias but the picked one goes back
         * to its manifest state, so picking [DEFAULT] restores a fresh install's setup.
         */
        fun apply(context: Context, icon: AppIcon): Boolean {
            val pm = context.packageManager
            fun set(item: AppIcon, state: Int) =
                pm.setComponentEnabledSetting(item.component(context), state, DONT_KILL_APP)
            return try {
                set(icon, if (icon == DEFAULT) COMPONENT_ENABLED_STATE_DEFAULT else COMPONENT_ENABLED_STATE_ENABLED)
                for (other in entries) {
                    if (other != icon) {
                        set(other, if (other == DEFAULT) COMPONENT_ENABLED_STATE_DISABLED else COMPONENT_ENABLED_STATE_DEFAULT)
                    }
                }
                true
            } catch (e: IllegalArgumentException) {
                false // an alias missing from the manifest
            } catch (e: SecurityException) {
                false
            }
        }
    }
}
