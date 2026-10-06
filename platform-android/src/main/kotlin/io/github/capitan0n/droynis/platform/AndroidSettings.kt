package io.github.capitan0n.droynis.platform

import android.content.ContentResolver
import android.os.Build
import android.provider.Settings
import io.github.capitan0n.droynis.checks.base.REDACTED_SETTINGS
import io.github.capitan0n.droynis.checks.base.SETTINGS_REDACTION_SDK
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

internal class AndroidSettings(private val resolver: ContentResolver) : SystemSettings {

    override fun global(key: String): Reading<String?> =
        read("Settings.Global", key) { Settings.Global.getString(resolver, key) }

    override fun secure(key: String): Reading<String?> =
        read("Settings.Secure", key) { Settings.Secure.getString(resolver, key) }

    override fun system(key: String): Reading<String?> =
        read("Settings.System", key) { Settings.System.getString(resolver, key) }

    // A readable but unset key is Value(null); access denied (hidden keys on API 31+) is Unavailable.
    private inline fun read(table: String, key: String, get: () -> String?): Reading<String?> {
        val source = Source("$table \"$key\"")
        return probe(source) { Reading.Value(get(), source) }
    }
}

/**
 * Reads settings as Droynis, and through a privileged shell (Shizuku or root), while one is ready,
 * only where that read proves nothing: a key Android hides from apps, or one Android 17 redacts
 * for them. Anything the shell can't read keeps the app's own reading.
 */
internal class ShellBackedSettings(
    private val local: SystemSettings,
    private val shells: ShellRouter,
) : SystemSettings {

    override fun global(key: String) = read("global", key, local.global(key))

    override fun secure(key: String) = read("secure", key, local.secure(key))

    override fun system(key: String) = read("system", key, local.system(key))

    private fun read(table: String, key: String, own: Reading<String?>): Reading<String?> {
        val unproven = own is Reading.Unavailable ||
            (key in REDACTED_SETTINGS && Build.VERSION.SDK_INT >= SETTINGS_REDACTION_SDK)
        if (!unproven) return own
        val shell = shells.active() ?: return own
        return shell.readSetting(table, key).takeIf { it is Reading.Value } ?: own
    }
}
