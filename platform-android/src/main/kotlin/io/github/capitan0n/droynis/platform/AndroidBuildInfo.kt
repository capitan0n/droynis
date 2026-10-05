package io.github.capitan0n.droynis.platform

import android.os.Build
import io.github.capitan0n.droynis.checks.base.BuildInfo
import io.github.capitan0n.droynis.checks.base.DeviceSummary
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source

internal object AndroidBuildInfo : BuildInfo {

    // Passed through raw, empty included: the check decides what is parseable.
    override fun securityPatch(): Reading<String> =
        Reading.Value(Build.VERSION.SECURITY_PATCH.orEmpty(), Source("Build.VERSION.SECURITY_PATCH"))

    // Deliberately no serial number or other hardware identifier.
    override fun device(): DeviceSummary = DeviceSummary(
        manufacturer = Build.MANUFACTURER.orEmpty(),
        model = Build.MODEL.orEmpty(),
        androidVersion = Build.VERSION.RELEASE.orEmpty(),
        sdkInt = Build.VERSION.SDK_INT,
        securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
        buildId = Build.ID.orEmpty(),
        kernel = System.getProperty("os.version"),
    )
}
