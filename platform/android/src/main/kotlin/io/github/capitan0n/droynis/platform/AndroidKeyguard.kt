package io.github.capitan0n.droynis.platform

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import io.github.capitan0n.droynis.checks.base.Keyguard
import io.github.capitan0n.droynis.checks.base.PasswordComplexity
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

internal class AndroidKeyguard(private val context: Context) : Keyguard {

    override fun isDeviceSecure(): Reading<Boolean> {
        val source = Source("KeyguardManager.isDeviceSecure()")
        val keyguard = context.getSystemService(KeyguardManager::class.java)
            ?: return Reading.Unsupported("no KeyguardManager service", source)
        return probe(source) { Reading.Value(keyguard.isDeviceSecure, source) }
    }

    override fun passwordComplexity(): Reading<PasswordComplexity> {
        val source = Source("DevicePolicyManager.getPasswordComplexity()")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Reading.Unsupported("needs API 29", source)
        }
        val policy = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Reading.Unsupported("no DevicePolicyManager service", source)
        return probe(source) {
            when (val code = policy.passwordComplexity) {
                DevicePolicyManager.PASSWORD_COMPLEXITY_NONE -> Reading.Value(PasswordComplexity.NONE, source)
                DevicePolicyManager.PASSWORD_COMPLEXITY_LOW -> Reading.Value(PasswordComplexity.LOW, source)
                DevicePolicyManager.PASSWORD_COMPLEXITY_MEDIUM -> Reading.Value(PasswordComplexity.MEDIUM, source)
                DevicePolicyManager.PASSWORD_COMPLEXITY_HIGH -> Reading.Value(PasswordComplexity.HIGH, source)
                else -> Reading.Unavailable("unknown complexity code $code", source)
            }
        }
    }
}
