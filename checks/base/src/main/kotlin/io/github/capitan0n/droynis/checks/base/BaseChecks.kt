package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Check

/** Registry of base-tier checks, in display order. Adding a check means one class plus one line here. */
fun baseChecks(probes: BaseProbes): List<Check> = listOf(
    // Device integrity
    SecurityPatchAgeCheck(probes.build),
    VendorPatchCheck(probes.build, probes.attestation, probes.properties),
    StorageEncryptionCheck(probes.policy),
    BootloaderCheck(probes.attestation, probes.properties),
    OemUnlockingCheck(probes.properties),
    RootAccessCheck(probes.files, probes.packages),
    AndroidBuildCheck(probes.build, probes.properties),
    WebViewCheck(probes.webView),
    AdvancedProtectionCheck(probes.policy),
    // Access control
    LockScreenCheck(probes.keyguard),
    LockStrengthCheck(probes.keyguard),
    ScreenTimeoutCheck(probes.settings),
    LockDelayCheck(probes.settings, probes.keyguard),
    StayAwakeCheck(probes.settings),
    PasswordVisibilityCheck(probes.settings),
    LockScreenNotificationsCheck(probes.settings),
    RemoteLockCheck(probes.policy, probes.packages),
    DeveloperOptionsCheck(probes.settings),
    UsbDebuggingCheck(probes.settings),
    WirelessDebuggingCheck(probes.settings),
    // Apps and permissions
    AccessibilityServicesCheck(probes.accessibility, probes.packages),
    DeviceAdminsCheck(probes.policy, probes.packages),
    NotificationAccessCheck(probes.settings, probes.packages),
    SmsAccessCheck(probes.permissions, probes.defaultApps, probes.packages),
    SmsSendingCheck(probes.permissions, probes.defaultApps, probes.packages),
    KeyboardAppsCheck(probes.inputMethods),
    DebuggableAppsCheck(probes.packages),
    UnknownSourceAppsCheck(probes.packages),
    OutdatedAppsCheck(probes.packages),
    // Network
    PrivateDnsCheck(probes.network),
    VpnCheck(probes.network),
    WifiSecurityCheck(probes.network),
    HttpProxyCheck(probes.network),
    Cellular2gCheck(probes.cellular, probes.settings, probes.properties),
    UserCertificatesCheck(probes.certificates),
    BluetoothCheck(probes.settings),
    NfcCheck(probes.radios),
    LocationCheck(probes.radios),
    ScanningCheck(probes.settings),
)
