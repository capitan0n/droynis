package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Reading
import java.time.LocalDate

/**
 * Read-only access to the Settings provider. A key that is readable but unset is `Value(null)`;
 * each check decides what "unset" means for its key.
 */
interface SystemSettings {
    fun global(key: String): Reading<String?>
    fun secure(key: String): Reading<String?>
    fun system(key: String): Reading<String?>
}

interface Keyguard {
    /** `KeyguardManager.isDeviceSecure()`: a PIN, pattern or password is set (SIM PIN excluded). */
    fun isDeviceSecure(): Reading<Boolean>

    /** Coarse strength bucket of the screen lock (API 29+); never the credential itself. */
    fun passwordComplexity(): Reading<PasswordComplexity>
}

/** Mirrors `DevicePolicyManager.PASSWORD_COMPLEXITY_*`. */
enum class PasswordComplexity { NONE, LOW, MEDIUM, HIGH }

interface BuildInfo {
    /** `Build.VERSION.SECURITY_PATCH` as reported by the OS, e.g. "2026-09-05". */
    fun securityPatch(): Reading<String>

    /** Descriptive facts for the device card and reports. Never includes hardware identifiers. */
    fun device(): DeviceSummary
}

data class DeviceSummary(
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val sdkInt: Int,
    val securityPatch: String,
    val buildId: String,
    val kernel: String?,
    /** `Build.TYPE`: "user" on production phones, "userdebug" or "eng" on debuggable builds. */
    val buildType: String,
    /** `Build.TAGS`, e.g. "release-keys"; "test-keys" means the public AOSP signing keys. */
    val buildTags: String,
)

/** Mirrors `DevicePolicyManager.ENCRYPTION_STATUS_*`. */
enum class EncryptionStatus { UNSUPPORTED, INACTIVE, ACTIVATING, ACTIVE_DEFAULT_KEY, ACTIVE, ACTIVE_PER_USER }

/** An app as shown to the user: its package name and its human-readable label. */
data class AppRef(val packageName: String, val label: String)

data class AdminApp(
    val app: AppRef,
    val isDeviceOwner: Boolean,
    val isProfileOwner: Boolean,
    /** Declares the force-lock policy; null when its declaration could not be read. */
    val canLock: Boolean? = null,
    /** Declares the wipe-data policy (erase the phone); null when its declaration could not be read. */
    val canWipe: Boolean? = null,
)

interface DevicePolicy {
    fun encryptionStatus(): Reading<EncryptionStatus>

    fun activeAdmins(): Reading<List<AdminApp>>

    /** Android 16+ Advanced Protection mode; Unsupported on older releases. */
    fun advancedProtection(): Reading<Boolean>
}

interface AccessibilityProbe {
    /** Apps whose accessibility services are currently enabled. */
    fun enabledServices(): Reading<List<AppRef>>
}

data class InstalledApp(
    val packageName: String,
    val isSystem: Boolean,
    val isDebuggable: Boolean,
    /** Package that installed the app, or null when unknown (for example adb). */
    val installer: String?,
    /** The Android API level the app was built for (`targetSdkVersion`). */
    val targetSdk: Int,
    /** False when the app is disabled, for example a system app the user turned off. */
    val isEnabled: Boolean = true,
    /** The app's Linux uid, which dumpsys prints instead of package names in places. */
    val uid: Int? = null,
)

interface PackageInventory {
    /** Every app visible to Droynis, except Droynis itself. */
    fun installedApps(): Reading<List<InstalledApp>>

    /** The app's label, falling back to its package name. */
    fun label(packageName: String): String
}

enum class Transport { WIFI, CELLULAR, ETHERNET, VPN, BLUETOOTH, OTHER }

data class NetworkSnapshot(
    val transports: Set<Transport>,
    val validated: Boolean,
    val metered: Boolean,
    /** Null below API 28, where the platform does not report it. */
    val privateDnsActive: Boolean?,
    /** Set only in strict ("hostname") mode. */
    val privateDnsServer: String?,
    val dnsServers: List<String>,
    val interfaceName: String?,
    /** Security of the Wi-Fi network in use (API 31+); null when not on Wi-Fi or not reported. */
    val wifiSecurity: WifiSecurity? = null,
    /** This device's addresses on the network, with prefix length, e.g. "192.168.1.20/24". */
    val addresses: List<String> = emptyList(),
    /** "host:port" or a PAC URL when the network sets an HTTP proxy, else null. */
    val httpProxy: String? = null,
) {
    val usesVpn: Boolean get() = Transport.VPN in transports
}

/** Mirrors `WifiInfo.SECURITY_TYPE_*`, grouped the way Settings names them. */
enum class WifiSecurity(val label: String) {
    OPEN("open, no encryption"),
    WEP("WEP"),
    WPA_PERSONAL("WPA/WPA2-Personal"),
    WPA3_PERSONAL("WPA3-Personal"),
    ENTERPRISE("WPA-Enterprise"),
    OWE("Enhanced Open (OWE)"),
    WAPI("WAPI"),
    PASSPOINT("Passpoint"),
    DPP("Easy Connect (DPP)"),
    OTHER("other"),
    UNKNOWN("unknown"),
}

interface NetworkProbe {
    /** The default network, or `Value(null)` when the device is offline. */
    fun activeNetwork(): Reading<NetworkSnapshot?>

    /**
     * Every connected network that carries internet traffic, the default one included: mobile data
     * stays connected next to Wi-Fi on most phones. Each with its own proxy, such as one an APN sets.
     */
    fun allNetworks(): Reading<List<NetworkSnapshot>>
}

data class UserCertificate(val subject: String, val expires: LocalDate?)

interface CertificateStore {
    /** CA certificates the user (or an app or admin on their behalf) installed. */
    fun userCertificates(): Reading<List<UserCertificate>>
}

interface RadioProbe {
    /** Unsupported when the device has no NFC hardware. */
    fun nfcEnabled(): Reading<Boolean>

    /** The system-wide Location switch. */
    fun locationEnabled(): Reading<Boolean>
}

/** An enabled input method; [isSystem] is true for keyboards that are part of the system image. */
data class Keyboard(val app: AppRef, val isSystem: Boolean)

interface InputMethodProbe {
    fun enabledKeyboards(): Reading<List<Keyboard>>
}

/**
 * Android system properties as `getprop` lists them. Properties this app may not read are simply
 * missing from the map, so a missing key means "not visible", never "false".
 */
interface SystemProperties {
    fun all(): Reading<Map<String, String>>
}

interface FileProbe {
    /** The subset of [paths] that exist and are visible to this app. */
    fun existing(paths: List<String>): Reading<List<String>>
}

/** Mirrors KeyMint `SecurityLevel`: where the attested key lives. */
enum class SecurityLevel { SOFTWARE, TRUSTED_ENVIRONMENT, STRONG_BOX }

/** Mirrors KeyMint `VerifiedBootState`, with the boot screen colour Android shows for each. */
enum class VerifiedBootState(val label: String) {
    VERIFIED("verified (green)"),
    SELF_SIGNED("custom key (yellow)"),
    UNVERIFIED("not verified (orange)"),
    FAILED("failed (red)"),
}

data class RootOfTrust(val deviceLocked: Boolean, val verifiedBootState: VerifiedBootState)

/** What a key attestation certificate says about the device. */
data class KeyAttestation(
    val attestationVersion: Int,
    val securityLevel: SecurityLevel,
    /** Absent from some old or software-only attestations. */
    val rootOfTrust: RootOfTrust?,
    /** Attested OS patch level as YYYYMM, when the certificate carries it. */
    val osPatchLevel: Int?,
    /** Attested vendor image patch level, YYYYMMDD (some report YYYYMM); Keymaster 4 and later. */
    val vendorPatchLevel: Int? = null,
    /** Attested boot image (kernel) patch level, YYYYMMDD (some report YYYYMM); Keymaster 4 and later. */
    val bootPatchLevel: Int? = null,
)

interface AttestationProbe {
    /** Creates a throwaway key with an attestation certificate and reports what it says. */
    fun attest(): Reading<KeyAttestation>
}

data class WebViewInfo(val packageName: String, val versionName: String, val lastUpdated: LocalDate)

interface WebViewProbe {
    /** The package that provides WebView, or `Value(null)` when the device has none. */
    fun provider(): Reading<WebViewInfo?>
}

interface PermissionProbe {
    /**
     * Apps other than Droynis that hold any of [permissions] right now (granted, not just
     * requested), with the ones each holds.
     */
    fun holders(permissions: Set<String>): Reading<Map<String, Set<String>>>
}

interface DefaultAppsProbe {
    /** `Telephony.Sms.getDefaultSmsPackage`: null on a phone without SMS or a default SMS app. */
    fun smsApp(): Reading<String?>

    /** `TelecomManager.getDefaultDialerPackage`: null without a default phone app. */
    fun phoneApp(): Reading<String?>
}

/** Everything the base-tier checks read. Implemented by :platform-android. */
interface BaseProbes {
    val settings: SystemSettings
    val keyguard: Keyguard
    val build: BuildInfo
    val policy: DevicePolicy
    val accessibility: AccessibilityProbe
    val packages: PackageInventory
    val network: NetworkProbe
    val certificates: CertificateStore
    val radios: RadioProbe
    val inputMethods: InputMethodProbe
    val properties: SystemProperties
    val files: FileProbe
    val attestation: AttestationProbe
    val webView: WebViewProbe
    val permissions: PermissionProbe
    val defaultApps: DefaultAppsProbe
    val cellular: CellularProbe
}
