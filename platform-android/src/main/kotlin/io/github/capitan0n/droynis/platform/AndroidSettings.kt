package io.github.capitan0n.droynis.platform

import android.content.ContentResolver
import android.provider.Settings
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

internal class AndroidSettings(private val resolver: ContentResolver) : SystemSettings {

    override fun global(key: String): Reading<String> {
        val source = Source("Settings.Global \"$key\"")
        return probe(source) {
            Settings.Global.getString(resolver, key)
                ?.let { Reading.Value(it, source) }
                ?: Reading.Unavailable("not set", source)
        }
    }
}
