package io.github.capitan0n.droynis.platform

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.security.advancedprotection.AdvancedProtectionManager
import io.github.capitan0n.droynis.checks.base.AdminApp
import io.github.capitan0n.droynis.checks.base.AppRef
import io.github.capitan0n.droynis.checks.base.DevicePolicy
import io.github.capitan0n.droynis.checks.base.EncryptionStatus
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

internal class AndroidDevicePolicy(
    private val context: Context,
    private val label: (String) -> String,
) : DevicePolicy {

    override fun encryptionStatus(): Reading<EncryptionStatus> {
        val source = Source("DevicePolicyManager.getStorageEncryptionStatus()")
        val policy = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Reading.Unsupported("no DevicePolicyManager service", source)
        return probe(source) {
            val status = when (val code = policy.storageEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> EncryptionStatus.UNSUPPORTED
                DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> EncryptionStatus.INACTIVE
                @Suppress("DEPRECATION") // still returned by older releases
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING -> EncryptionStatus.ACTIVATING
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> EncryptionStatus.ACTIVE_DEFAULT_KEY
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE -> EncryptionStatus.ACTIVE
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> EncryptionStatus.ACTIVE_PER_USER
                else -> return@probe Reading.Unavailable("unknown encryption status $code", source)
            }
            Reading.Value(status, source)
        }
    }

    override fun activeAdmins(): Reading<List<AdminApp>> {
        val source = Source("DevicePolicyManager.getActiveAdmins()")
        val policy = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Reading.Unsupported("no DevicePolicyManager service", source)
        return probe(source) {
            val admins = policy.activeAdmins.orEmpty()
                .map { it.packageName }
                .distinct()
                .map { pkg ->
                    AdminApp(
                        app = AppRef(pkg, label(pkg)),
                        isDeviceOwner = policy.isDeviceOwnerApp(pkg),
                        isProfileOwner = policy.isProfileOwnerApp(pkg),
                    )
                }
            Reading.Value(admins, source)
        }
    }

    override fun advancedProtection(): Reading<Boolean> {
        val source = Source("AdvancedProtectionManager.isAdvancedProtectionEnabled()")
        if (Build.VERSION.SDK_INT < ANDROID_16) {
            return Reading.Unsupported("needs Android 16 (API 36)", source)
        }
        val manager = context.getSystemService(AdvancedProtectionManager::class.java)
            ?: return Reading.Unsupported("no AdvancedProtectionManager service", source)
        return probe(source) { Reading.Value(manager.isAdvancedProtectionEnabled, source) }
    }

    private companion object {
        const val ANDROID_16 = 36
    }
}
