package io.github.capitan0n.droynis.platform

import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import io.github.capitan0n.droynis.checks.base.BiometricAvailability
import io.github.capitan0n.droynis.checks.base.BiometricModality
import io.github.capitan0n.droynis.checks.base.BiometricProbe
import io.github.capitan0n.droynis.checks.base.BiometricState
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * `BiometricManager.canAuthenticate(int)` (API 30+, the normal permission USE_BIOMETRIC) once per
 * class, and the biometric hardware features. It says whether some biometric of a class is
 * enrolled, never which one, and never reports convenience (Class 1) sensors.
 */
internal class AndroidBiometrics(private val context: Context) : BiometricProbe {

    override fun state(): Reading<BiometricState> {
        val source = Source("BiometricManager.canAuthenticate()")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return Reading.Unsupported("needs API 30", source)
        }
        val manager = context.getSystemService(BiometricManager::class.java)
            ?: return Reading.Unsupported("no BiometricManager service", source)
        return probe(source) {
            val weak = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            val strong = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            Reading.Value(BiometricState(availability(weak), availability(strong), weak, strong, hardware()), source)
        }
    }

    @TargetApi(Build.VERSION_CODES.R)
    private fun availability(code: Int): BiometricAvailability = when (code) {
        BiometricManager.BIOMETRIC_SUCCESS -> BiometricAvailability.ENROLLED
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricAvailability.NONE_ENROLLED
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricAvailability.NO_HARDWARE
        else -> BiometricAvailability.OTHER
    }

    @TargetApi(Build.VERSION_CODES.R)
    private fun hardware(): Set<BiometricModality> {
        val features = context.packageManager
        return buildSet {
            if (features.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) add(BiometricModality.FINGERPRINT)
            if (features.hasSystemFeature(PackageManager.FEATURE_FACE)) add(BiometricModality.FACE)
            if (features.hasSystemFeature(PackageManager.FEATURE_IRIS)) add(BiometricModality.IRIS)
        }
    }
}
