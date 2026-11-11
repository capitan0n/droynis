package io.github.capitan0n.droynis.platform

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.os.UserManager
import io.github.capitan0n.droynis.checks.base.ProfileProbe
import io.github.capitan0n.droynis.checks.base.ProfileState
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

/**
 * The profiles of the user Droynis runs in, and whether an organization owns the phone. Neither
 * call needs a permission: UserManagerService answers any app about its own profile group, hidden
 * profiles such as a Private Space included, and DevicePolicyManagerService checks no caller for
 * `isOrganizationOwnedDeviceWithManagedProfile` (both read in AOSP's main branch, November 2026).
 */
internal class AndroidProfiles(private val context: Context) : ProfileProbe {

    override fun state(): Reading<ProfileState> {
        val source = Source("UserManager.getUserProfiles()")
        val users = context.getSystemService(UserManager::class.java)
            ?: return Reading.Unsupported("no user service", source)
        return probe(source) {
            Reading.Value(ProfileState(profiles = users.userProfiles.size, isSystemUser = users.isSystemUser), source)
        }
    }

    override fun organizationOwned(): Reading<Boolean> {
        val source = Source("DevicePolicyManager.isOrganizationOwnedDeviceWithManagedProfile()")
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return Reading.Unsupported("needs Android 11 (API 30)", source)
        }
        val policy = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Reading.Unsupported("no DevicePolicyManager service", source)
        return probe(source) { Reading.Value(policy.isOrganizationOwnedDeviceWithManagedProfile, source) }
    }
}
