package io.github.capitan0n.droynis.platform

import android.Manifest
import org.junit.Assert.assertTrue
import org.junit.Test

class SensitivePermissionTest {

    @Test
    fun everyPermissionNameExistsInTheSdk() {
        val sdk = Manifest.permission::class.java.fields.mapNotNull { it.get(null) as? String }.toSet()

        for (group in SensitivePermission.entries) {
            for (name in group.qualified) assertTrue("$group: $name", name in sdk)
        }
    }
}
