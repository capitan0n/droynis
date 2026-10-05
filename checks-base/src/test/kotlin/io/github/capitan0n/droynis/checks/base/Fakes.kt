package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.Status
import java.time.ZoneOffset
import java.time.ZonedDateTime

private val FAKE = Source("fake")

fun <T> value(value: T): Reading<T> = Reading.Value(value, FAKE)

fun unavailable(reason: String = "not set"): Reading<Nothing> = Reading.Unavailable(reason, FAKE)

fun unsupported(reason: String = "needs API 29"): Reading<Nothing> = Reading.Unsupported(reason, FAKE)

fun scanContext(year: Int = 2026, month: Int = 10, day: Int = 1, sdk: Int = 37) = ScanContext(
    startedAt = ZonedDateTime.of(year, month, day, 12, 0, 0, 0, ZoneOffset.UTC),
    sdkInt = sdk,
)

suspend fun Check.outcome(): Outcome = run(scanContext())

suspend fun Check.status(): Status = outcome().status

/** Unset keys read as `Value(null)`, like a readable key that was never written. */
class FakeSettings(
    private val global: Map<String, Reading<String?>> = emptyMap(),
    private val secure: Map<String, Reading<String?>> = emptyMap(),
    private val system: Map<String, Reading<String?>> = emptyMap(),
) : SystemSettings {
    override fun global(key: String): Reading<String?> = global[key] ?: value(null)
    override fun secure(key: String): Reading<String?> = secure[key] ?: value(null)
    override fun system(key: String): Reading<String?> = system[key] ?: value(null)
}

class FakeKeyguard(
    private val secure: Reading<Boolean>,
    private val complexity: Reading<PasswordComplexity> = unsupported(),
) : Keyguard {
    override fun isDeviceSecure() = secure
    override fun passwordComplexity() = complexity
}

class FakeBuildInfo(
    private val patch: Reading<String>,
    private val type: String = "user",
    private val tags: String = "release-keys",
) : BuildInfo {
    override fun securityPatch() = patch
    override fun device() = DeviceSummary("Fairphone", "FP6", "17", 37, "2026-09-05", "TEST.1", "6.6.0", type, tags)
}

class FakePolicy(
    private val encryption: Reading<EncryptionStatus> = value(EncryptionStatus.ACTIVE_PER_USER),
    private val admins: Reading<List<AdminApp>> = value(emptyList()),
    private val advancedProtection: Reading<Boolean> = value(false),
) : DevicePolicy {
    override fun encryptionStatus() = encryption
    override fun activeAdmins() = admins
    override fun advancedProtection() = advancedProtection
}

class FakeAccessibility(private val services: Reading<List<AppRef>> = value(emptyList())) : AccessibilityProbe {
    override fun enabledServices() = services
}

class FakePackages(
    private val apps: Reading<List<InstalledApp>> = value(emptyList()),
    private val labels: Map<String, String> = emptyMap(),
) : PackageInventory {
    override fun installedApps() = apps
    override fun label(packageName: String) = labels[packageName] ?: packageName
}

class FakeNetwork(private val snapshot: Reading<NetworkSnapshot?>) : NetworkProbe {
    override fun activeNetwork() = snapshot
}

fun wifi(
    privateDns: Boolean? = false,
    server: String? = null,
    vpn: Boolean = false,
    security: WifiSecurity? = WifiSecurity.WPA_PERSONAL,
) = NetworkSnapshot(
    transports = if (vpn) setOf(Transport.WIFI, Transport.VPN) else setOf(Transport.WIFI),
    validated = true,
    metered = false,
    privateDnsActive = privateDns,
    privateDnsServer = server,
    dnsServers = listOf("192.168.1.1"),
    interfaceName = "wlan0",
    wifiSecurity = security,
)

fun cellular() = NetworkSnapshot(
    transports = setOf(Transport.CELLULAR),
    validated = true,
    metered = true,
    privateDnsActive = true,
    privateDnsServer = null,
    dnsServers = listOf("10.0.0.1"),
    interfaceName = "rmnet0",
)

class FakeCertificates(private val certs: Reading<List<UserCertificate>> = value(emptyList())) : CertificateStore {
    override fun userCertificates() = certs
}

class FakeRadios(private val nfc: Reading<Boolean> = value(false)) : RadioProbe {
    override fun nfcEnabled() = nfc
}

class FakeInputMethods(private val keyboards: Reading<List<Keyboard>> = value(emptyList())) : InputMethodProbe {
    override fun enabledKeyboards() = keyboards
}

class FakeProperties(private val props: Reading<Map<String, String>> = value(emptyMap())) : SystemProperties {
    constructor(vararg pairs: Pair<String, String>) : this(value(mapOf(*pairs)))

    override fun all() = props
}

class FakeFiles(private val present: Reading<List<String>> = value(emptyList())) : FileProbe {
    override fun existing(paths: List<String>): Reading<List<String>> = when (present) {
        is Reading.Value -> value(paths.filter { it in present.value })
        else -> present
    }
}

class FakeAttestation(private val attestation: Reading<KeyAttestation> = unsupported("no attestation")) : AttestationProbe {
    override fun attest() = attestation
}

fun attested(
    locked: Boolean,
    state: VerifiedBootState = VerifiedBootState.VERIFIED,
    level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
) = value(KeyAttestation(300, level, RootOfTrust(locked, state), osPatchLevel = 202609))

class FakeWebView(private val info: Reading<WebViewInfo?> = value(null)) : WebViewProbe {
    override fun provider() = info
}

class FakeProbes(
    override val settings: SystemSettings = FakeSettings(),
    override val keyguard: Keyguard = FakeKeyguard(unavailable()),
    override val build: BuildInfo = FakeBuildInfo(unavailable()),
    override val policy: DevicePolicy = FakePolicy(),
    override val accessibility: AccessibilityProbe = FakeAccessibility(),
    override val packages: PackageInventory = FakePackages(),
    override val network: NetworkProbe = FakeNetwork(value(null)),
    override val certificates: CertificateStore = FakeCertificates(),
    override val radios: RadioProbe = FakeRadios(),
    override val inputMethods: InputMethodProbe = FakeInputMethods(),
    override val properties: SystemProperties = FakeProperties(),
    override val files: FileProbe = FakeFiles(),
    override val attestation: AttestationProbe = FakeAttestation(),
    override val webView: WebViewProbe = FakeWebView(),
) : BaseProbes
