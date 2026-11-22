package io.github.capitan0n.droynis.platform

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.github.capitan0n.droynis.checks.base.KeyAttestation
import io.github.capitan0n.droynis.checks.base.StrongBoxProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/** StrongBox as the package manager declares it, and a throwaway key made in it. No permission. */
internal class AndroidStrongBox(private val context: Context) : StrongBoxProbe {

    override fun feature(): Reading<Int?> {
        val source = Source("PackageManager.FEATURE_STRONGBOX_KEYSTORE")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return Reading.Unsupported("needs Android 9", source)
        return probe(source) {
            // hasSystemFeature() can't tell the version; the feature list carries it.
            val declared = context.packageManager.systemAvailableFeatures
                .firstOrNull { it.name == PackageManager.FEATURE_STRONGBOX_KEYSTORE }
            Reading.Value(declared?.version, source)
        }
    }

    override fun attest(): Reading<KeyAttestation> = AndroidAttestation.attestStrongBox()
}
