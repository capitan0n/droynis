package io.github.capitan0n.droynis.platform

import android.app.admin.DeviceAdminInfo
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Build
import android.security.advancedprotection.AdvancedProtectionManager
import io.github.capitan0n.droynis.checks.base.AdminApp
import io.github.capitan0n.droynis.checks.base.AppRef
import io.github.capitan0n.droynis.checks.base.DevicePolicy
import io.github.capitan0n.droynis.checks.base.EncryptionStatus
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.io.IOException
import org.xmlpull.v1.XmlPullParserException

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

    // Two checks read the admins; each parse opens the admin's own resources.
    private val admins = ScanCache<List<AdminApp>>()

    override fun activeAdmins(): Reading<List<AdminApp>> = admins.get(::readAdmins)

    /** Drops the admins kept for one scan. */
    fun clearCache() = admins.clear()

    private fun readAdmins(): Reading<List<AdminApp>> {
        val source = Source("DevicePolicyManager.getActiveAdmins()")
        val policy = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Reading.Unsupported("no DevicePolicyManager service", source)
        return probe(source) {
            val admins = policy.activeAdmins.orEmpty()
                .groupBy { it.packageName }
                .map { (pkg, receivers) ->
                    val declared = receivers.map(::declaredPolicies)
                    AdminApp(
                        app = AppRef(pkg, label(pkg)),
                        isDeviceOwner = policy.isDeviceOwnerApp(pkg),
                        isProfileOwner = policy.isProfileOwnerApp(pkg),
                        canLock = declared.anyUses(DeviceAdminInfo.USES_POLICY_FORCE_LOCK),
                        canWipe = declared.anyUses(DeviceAdminInfo.USES_POLICY_WIPE_DATA),
                    )
                }
            Reading.Value(admins, source)
        }
    }

    /**
     * The policies an admin receiver declares in its `android.app.device_admin` metadata; Android
     * grants an active admin exactly these. `hasGrantedPolicy()` would tell, but in Android 17 it
     * answers only the admin itself (`DevicePolicyManagerService.hasGrantedPolicy`).
     */
    private fun declaredPolicies(receiver: ComponentName): DeviceAdminInfo? =
        try {
            @Suppress("DEPRECATION") // the ComponentInfoFlags overload needs API 33
            val info = context.packageManager.getReceiverInfo(receiver, PackageManager.GET_META_DATA)
            DeviceAdminInfo(context, ResolveInfo().apply { activityInfo = info })
        } catch (e: PackageManager.NameNotFoundException) {
            null
        } catch (e: XmlPullParserException) {
            null
        } catch (e: IOException) {
            null
        } catch (e: RuntimeException) {
            // e.g. Resources.NotFoundException from a broken metadata reference: one admin stays unknown.
            null
        }

    /** True if any receiver declares [policy]; null if none does but one could not be read. */
    private fun List<DeviceAdminInfo?>.anyUses(policy: Int): Boolean? = when {
        any { it?.usesPolicy(policy) == true } -> true
        any { it == null } -> null
        else -> false
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
