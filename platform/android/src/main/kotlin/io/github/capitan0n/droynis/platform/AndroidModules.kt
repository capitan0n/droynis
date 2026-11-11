package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.github.capitan0n.droynis.checks.base.ModuleMetadata
import io.github.capitan0n.droynis.checks.base.ModuleProbe
import io.github.capitan0n.droynis.checks.base.PlaySystemUpdateCheck
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * The module metadata package, whose version name Settings shows as "Google Play system update".
 * The framework names it in `config_defaultModuleMetadataProvider`: `com.android.modulemetadata` in
 * AOSP, overlaid with Google's package on phones that get the updates. That resource is private, so
 * the two names are tried instead, Google's first.
 */
internal class AndroidModules(private val context: Context) : ModuleProbe {

    override fun metadata(): Reading<ModuleMetadata?> {
        val source = Source("PackageManager.getPackageInfo(module metadata).versionName")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Reading.Unsupported("needs Android 10 (API 29)", source)
        }
        return probe(source) {
            val found = PROVIDERS.firstNotNullOfOrNull { name ->
                versionName(name)?.let { ModuleMetadata(name, it) }
            }
            Reading.Value(found, source)
        }
    }

    /** Null when [packageName] isn't installed or has no version name. */
    @Suppress("DEPRECATION") // the PackageInfoFlags overload needs API 33
    private fun versionName(packageName: String): String? =
        try {
            context.packageManager.getPackageInfo(packageName, 0).versionName
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }

    private companion object {
        val PROVIDERS = listOf(PlaySystemUpdateCheck.GOOGLE_PROVIDER, "com.android.modulemetadata")
    }
}
