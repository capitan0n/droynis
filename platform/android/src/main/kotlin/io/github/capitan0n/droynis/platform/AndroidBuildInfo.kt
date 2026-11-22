package io.github.capitan0n.droynis.platform

import android.os.Build
import io.github.capitan0n.droynis.checks.base.BuildInfo
import io.github.capitan0n.droynis.checks.base.ChipInfo
import io.github.capitan0n.droynis.checks.base.DeviceSummary
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.time.Instant

internal object AndroidBuildInfo : BuildInfo {

    // Passed through raw, empty included: the check decides what is parseable.
    override fun securityPatch(): Reading<String> =
        Reading.Value(Build.VERSION.SECURITY_PATCH.orEmpty(), Source("Build.VERSION.SECURITY_PATCH"))

    override fun builtAt(): Reading<Instant> = Reading.Value(Instant.ofEpochMilli(Build.TIME), Source("Build.TIME"))

    // Deliberately no serial number or other hardware identifier.
    override fun device(): DeviceSummary = DeviceSummary(
        manufacturer = Build.MANUFACTURER.orEmpty(),
        model = Build.MODEL.orEmpty(),
        androidVersion = Build.VERSION.RELEASE.orEmpty(),
        sdkInt = Build.VERSION.SDK_INT,
        securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
        buildId = Build.ID.orEmpty(),
        kernel = System.getProperty("os.version"),
        buildType = Build.TYPE.orEmpty(),
        buildTags = Build.TAGS.orEmpty(),
    )

    // Build.SOC_* exist from Android 12; every field reads "unknown" (Build.UNKNOWN) when unset.
    override fun chip(): ChipInfo = ChipInfo(
        socManufacturer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) known(Build.SOC_MANUFACTURER) else null,
        socModel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) known(Build.SOC_MODEL) else null,
        hardware = known(Build.HARDWARE),
        board = known(Build.BOARD),
    )

    private fun known(value: String?): String? = value?.trim()?.takeIf { it.isNotEmpty() && it != Build.UNKNOWN }
}
