package io.github.capitan0n.droynis.platform

import android.content.Context
import android.os.Build
import io.github.capitan0n.droynis.checks.base.AccessibilityProbe
import io.github.capitan0n.droynis.checks.base.AttestationProbe
import io.github.capitan0n.droynis.checks.base.BaseProbes
import io.github.capitan0n.droynis.checks.base.BuildInfo
import io.github.capitan0n.droynis.checks.base.CertificateStore
import io.github.capitan0n.droynis.checks.base.DevicePolicy
import io.github.capitan0n.droynis.checks.base.FileProbe
import io.github.capitan0n.droynis.checks.base.InputMethodProbe
import io.github.capitan0n.droynis.checks.base.Keyguard
import io.github.capitan0n.droynis.checks.base.NetworkProbe
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.RadioProbe
import io.github.capitan0n.droynis.checks.base.SystemProperties
import io.github.capitan0n.droynis.checks.base.SystemSettings
import io.github.capitan0n.droynis.checks.base.WebViewProbe
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
    override val packages: PackageInventory = AndroidPackages(app)
    override val policy: DevicePolicy = AndroidDevicePolicy(app, packages::label)
    override val accessibility: AccessibilityProbe = AndroidAccessibility(app, packages::label)
    override val network: NetworkProbe = AndroidNetwork(app)
    override val certificates: CertificateStore = AndroidCertificates
    override val radios: RadioProbe = AndroidRadios(app)
    override val inputMethods: InputMethodProbe = AndroidInputMethods(app, packages::label)
    override val properties: SystemProperties = AndroidSystemProperties
    override val files: FileProbe = AndroidFiles
    override val attestation: AttestationProbe = AndroidAttestation
    override val webView: WebViewProbe = AndroidWebView

    /** Not a check: feeds the permission overview on the Tools screen. */
    val permissionAudit = AndroidPermissionAudit(app)

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
    } catch (e: Exception) {
        Reading.Unavailable("${e.javaClass.simpleName}: ${e.message}", source)
    }
