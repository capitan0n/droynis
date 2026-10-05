package io.github.capitan0n.droynis.platform

import android.content.ContentResolver
import android.provider.Settings
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
