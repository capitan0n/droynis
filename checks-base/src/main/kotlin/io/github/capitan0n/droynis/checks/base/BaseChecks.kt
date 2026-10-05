package io.github.capitan0n.droynis.checks.base

import io.github.capitan0n.droynis.core.Check

/** Registry of base-tier checks, in display order. Adding a check means one class plus one line here. */
fun baseChecks(probes: BaseProbes): List<Check> = listOf(
    // Device integrity
    SecurityPatchAgeCheck(probes.build),
    StorageEncryptionCheck(probes.policy),
    AdvancedProtectionCheck(probes.policy),
    // Access control
    LockScreenCheck(probes.keyguard),
    ScreenTimeoutCheck(probes.settings),
    PasswordVisibilityCheck(probes.settings),
    LockScreenNotificationsCheck(probes.settings),
    DeveloperOptionsCheck(probes.settings),
    UsbDebuggingCheck(probes.settings),
    WirelessDebuggingCheck(probes.settings),
    // Apps and permissions
    AccessibilityServicesCheck(probes.accessibility),
    DeviceAdminsCheck(probes.policy),
    NotificationAccessCheck(probes.settings, probes.packages),
    KeyboardAppsCheck(probes.inputMethods),
    DebuggableAppsCheck(probes.packages),
    UnknownSourceAppsCheck(probes.packages),
    // Network
    PrivateDnsCheck(probes.network),
    VpnCheck(probes.network),
    WifiSecurityCheck(probes.network),
    UserCertificatesCheck(probes.certificates),
    BluetoothCheck(probes.settings),
    NfcCheck(probes.radios),
)
