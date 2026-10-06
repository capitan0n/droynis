package io.github.capitan0n.droynis.platform

import android.content.Context
import android.os.Build
import android.os.Process
import io.github.capitan0n.droynis.checks.adb.AdbProbes
import io.github.capitan0n.droynis.checks.adb.Dumpsys
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
import io.github.capitan0n.droynis.checks.root.RootProbes
import io.github.capitan0n.droynis.checks.shizuku.PrivilegedShell
import io.github.capitan0n.droynis.checks.shizuku.ShizukuProbes
import io.github.capitan0n.droynis.core.Capabilities
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.platform.root.RootShell
import io.github.capitan0n.droynis.platform.shizuku.ShizukuShell
import java.time.ZonedDateTime

/** Android implementations of the probes: the only code checks reach the framework through. */
class AndroidPlatform(context: Context) : BaseProbes, AdbProbes, ShizukuProbes, RootProbes, AutoCloseable {
    private val app = context.applicationContext
    private val grants = AndroidGrants(app)

    /** Shizuku's state, its permission request, and Droynis' read-only shell through it. */
    val shizuku = ShizukuShell(app)

    /** The opt-in root tier: a read-only root shell, opened only while a scan runs. */
    override val root = RootShell(app)

    private val shells = ShellRouter(shizuku, root)

    override val settings: SystemSettings = ShellBackedSettings(AndroidSettings(app.contentResolver), shells)
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
    override val dumpsys: Dumpsys = RoutedDumpsys(grants, shells)
    override val shell: PrivilegedShell = shells

    /** Not a check: feeds the permission overview on the Tools screen. */
    val permissionAudit = AndroidPermissionAudit(app)

    /**
     * What adb granted right now, plus Shizuku while its shell is connected, plus root while it is
     * on and the root manager allowed the last shell.
     */
    fun detectGrants(): Set<Grant> = grants.detect() + listOfNotNull(
        Grant.SHIZUKU.takeIf { shizuku.isConnected },
        Grant.ROOT.takeIf { root.granted },
    )

    /**
     * Starts the Shizuku shell when Shizuku allows it, and the root shell when root is on, so a scan
     * uses every tier available. Blocks while they start, up to half a minute while the root manager
     * asks the user: call it off the main thread, and [scanFinished] after the scan.
     */
    fun newScanContext(): ScanContext {
        shizuku.connect()
        root.open()
        return ScanContext(
            startedAt = ZonedDateTime.now(),
            sdkInt = Build.VERSION.SDK_INT,
            capabilities = Capabilities(detectGrants()),
            appPackage = app.packageName,
            appUid = Process.myUid(),
        )
    }

    /** Ends the root shell: it is open only while a scan runs. */
    fun scanFinished() = root.close()

    /** Stops the Shizuku and root shells. */
    override fun close() {
        shizuku.close()
        root.close()
    }
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
