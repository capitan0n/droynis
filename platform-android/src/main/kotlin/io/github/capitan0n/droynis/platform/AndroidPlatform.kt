package io.github.capitan0n.droynis.platform

import android.content.Context
import android.os.Build
import io.github.capitan0n.droynis.checks.base.BaseProbes
import io.github.capitan0n.droynis.checks.base.BuildInfo
import io.github.capitan0n.droynis.checks.base.Keyguard
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.core.Capabilities
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import java.time.ZonedDateTime

/** Android implementations of the probes: the only code base-tier checks reach the framework through. */
class AndroidPlatform(context: Context) : BaseProbes {
    private val app = context.applicationContext

    override val settings: SystemSettings = AndroidSettings(app.contentResolver)
    override val keyguard: Keyguard = AndroidKeyguard(app)
    override val build: BuildInfo = AndroidBuildInfo

    /** Grant detection arrives with the ADB and Shizuku tiers; until then every scan is base tier. */
    fun newScanContext(): ScanContext = ScanContext(
        startedAt = ZonedDateTime.now(),
        sdkInt = Build.VERSION.SDK_INT,
        capabilities = Capabilities(),
    )
}

/** Runs one framework call and turns any failure into a [Reading] instead of an exception. */
internal inline fun <T> probe(source: Source, call: () -> Reading<T>): Reading<T> =
    try {
        call()
    } catch (e: SecurityException) {
        // e.g. a hidden Settings key read by an app targeting API 31+
        Reading.Unavailable("access denied: ${e.message}", source)
    } catch (e: LinkageError) {
        // the method is missing from this device's framework build
        Reading.Unsupported("${e.javaClass.simpleName}: ${e.message}", source)
    } catch (e: RuntimeException) {
        Reading.Unavailable("${e.javaClass.simpleName}: ${e.message}", source)
    }
