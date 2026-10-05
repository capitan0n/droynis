# Droynis design notes

Status: base tier, 30 checks (see the README for the list) and a Compose UI with dashboard,
checks, tools and help screens. This file records how the brief maps onto current Android
(API 37, October 2026) and the decisions taken so far.

## 1. Brief review: what does not hold on current Android

| # | Brief says | Reality | Decision |
|---|---|---|---|
| 1 | Verify boot state with on-device key attestation, like Auditor | The chain is signed in hardware, but the code that verifies it runs inside the OS being judged; a rooted OS can hook the verifier. Auditor is trustworthy because a *second* device or server verifies and pins. | Present it as posture ("self-attested"), never as proof. Allow exporting the raw chain for off-device verification. Trust both Google roots: the legacy RSA root and the ECDSA P-384 root that RKP devices use exclusively since April 2026. Reuse Auditor's (MIT) verified-boot key table and keep it current. |
| 2 | List apps with permissions, accessibility, admins… | Since API 30 package visibility hides most apps unless the app holds `QUERY_ALL_PACKAGES`. Without it, invisible apps produce false PASSes. | Declare `QUERY_ALL_PACKAGES` (fine on F-Droid; Play restricts it). |
| 3 | Base tier reports overlay, usage access, install-unknown, all-files, notification listener, VPN for every app | No uniform public API. These are app-ops or Settings keys of *other* apps: reading a foreign app-op mode via `AppOpsManager.unsafeCheckOpNoThrow` is version-dependent and visibility-filtered, some op strings are hidden (`android:request_install_packages`, `android:manage_external_storage`), and notification listeners / always-on VPN live in hidden `Settings.Secure` keys that apps targeting API 31+ may read only if the platform marks them `@Readable` (otherwise `SecurityException`). Which app owns the active VPN is shown only to that app. | Best effort in base tier, UNKNOWN on any failure. Authoritative via Shizuku (`appops get`, `settings get`). Public and reliable: accessibility (`ENABLED_ACCESSIBILITY_SERVICES`), device admins (`getActiveAdmins`), default SMS/dialer, runtime permissions, debuggable/targetSdk, installer. Checked against the Android 16 and 17 framework: `enabled_notification_listeners` and both `lock_screen_*` notification keys carry `@Readable` and are used; `always_on_vpn_app` does not, `enabled_input_methods` only up to target API 33 (keyboards come from `InputMethodManager` instead). |
| 4 | Probe at runtime instead of branching on Android version | Calling an API newer than the device throws `NoSuchMethodError`, and lint's `NewApi` fails the build without an `SDK_INT` guard. | Version checks decide *whether an API exists* (`CheckSpec.minSdk`, `SDK_INT` guards in adapters). Runtime probing handles *content*: missing settings, OEM differences, `SecurityException`. Every probe returns a `Reading` instead of throwing. |
| 5 | `PACKAGE_USAGE_STATS` is an ADB grant | It is an app-op the user can grant in Settings › Usage access. | Base-tier grant with an in-app prompt (`Grant.PACKAGE_USAGE_STATS`). |
| 6 | `READ_LOGS` grant survives reboots and unlocks logcat | Since Android 13 every logcat session also needs a per-session "Allow access to all device logs?" dialog, shown only while the app is in the foreground. SELinux denials are noisy on production builds. | Logcat scan is interactive only. For crash loops, evaluate `DropBoxManager` (`READ_LOGS` + usage access) instead of parsing logcat. |
| 7 | `DUMP` unlocks live dumpsys | It does, but SELinux still blocks `untrusted_app` from some services, and dumpsys output is unversioned, OEM-specific text that can include account names. | Parse narrowly, store only parsed fields as evidence, UNKNOWN on parse failure. |
| 8 | Shizuku, and "no non-SDK interfaces" | Typical Shizuku code wraps hidden AIDL interfaces (`IAppOpsService`…), which is non-SDK by definition. `Shizuku.newProcess` is private since Shizuku-API 13.1.5. | Use a Shizuku `UserService` (our code running as shell, UID 2000) that runs a fixed allowlist of read-only commands and returns text over our own AIDL. |
| 9 | A crashing or hanging check yields UNKNOWN | Coroutine timeouts only fire at suspension points; a blocking binder call cannot be interrupted. Native crashes and OOM kill the process. | Implemented: each check runs detached and races a timeout, so a hang costs one thread, not the scan. A separate scanner process is not worth it for v1. |
| 10 | Network off by default, revocation list opt-in | `INTERNET` is granted at install. Once declared, "off by default" cannot be verified from the manifest. | Ship without `INTERNET` (CI fails the build otherwise). Import the revocation list JSON through the Storage Access Framework, or provide a separate online flavor. |
| 11 | Distribute via F-Droid | Google's developer verification blocks apps from unregistered developers on certified devices (enforced since 2026-09-30 in Brazil, Indonesia, Singapore and Thailand; worldwide in 2027), F-Droid installs included. | A distribution decision, not a code one. Reproducible builds let F-Droid ship *your* signature, so the same key works if you choose to register. |
| 12 | Security patch age | Since mid-2025 most fixes ship in quarterly bulletins (March, June, September, December); monthly ones can be empty. `SECURITY_PATCH` is self-reported and vendors have over-claimed it before. | PASS up to 90 days, WARNING up to a year, CRITICAL beyond. Cross-check with the attested `osPatchLevel` once attestation lands. |
| 13 | Reports exclude IMEI, serial, phone number, account names | The base tier cannot read those anyway: IMEI and serial are privileged since API 29, and phone number and accounts need permissions Droynis does not request. The real leaks are the installed-app list (health, religion, politics…), CA certificate subjects (employer), Private DNS hostname and raw dumpsys text. | Export redacted by default (package names omitted or hashed); raw only on explicit choice. |
| 14 | Advanced Protection (API 36+) | Readable with the normal permission `QUERY_ADVANCED_PROTECTION_MODE`. It also blocks installs from unknown sources, which conflicts with F-Droid users. | INFO (no score impact), with that trade-off in the remediation text. |
| 15 | Developer options and USB debugging are plain public settings | Android 17 annotates `adb_enabled` and `development_settings_enabled` with `@Readable(redactedValue = "0")`: behind the platform flag `enable_redacted_value_for_readable`, every app with UID ≥ 10000 reads "0" whatever the real state, at any target SDK. The mechanism is absent from Android 16. `adb_wifi_enabled` is not redacted. | On API 37+ a "0" is UNKNOWN ("can't be verified"), never PASS; a "1" is still a real FAIL. The Shizuku tier (shell UID) will read the real value. |

Smaller points: StrongBox absence is not user-fixable (INFO, no score impact). Emulators have
adb on and no lock screen, so instrumented tests assert that a verdict was reached, not which.
AOSP/ATD emulator images do not exist for every API level; Google APIs images are fine for tests.

### Device state without privileges

- **Bootloader** (INTG-1040): an attested key's certificate carries `RootOfTrust` (device locked,
  verified boot state) as reported by the bootloader to the secure hardware. Droynis parses the
  KeyDescription extension with its own small DER reader (no Bouncy Castle) and only trusts TEE or
  StrongBox attestations. The chain is not yet checked against Google's roots, so this is posture,
  not proof (row 1). Without hardware attestation it falls back to `ro.boot.*` properties, which
  root can fake towards "locked" but which do not lie about "unlocked" on their own.
- **System properties** come from running `/system/bin/getprop` once per scan (cached 10 s).
  SELinux filters what an app may read; a missing property is "not visible", never "false".
  `sys.oem_unlock_allowed` is not readable on every device, so OEM unlocking can be UNKNOWN.
- **Root** (INTG-1050) is a heuristic: known su paths (existence only; Droynis never runs su) and
  root managers or hooking frameworks by package name. Hidden root (DenyList, Shamiko, KernelSU)
  is not detected, and the explanation says so.

## 2. Modules

```
core-model        Kotlin/JVM  Check contract, results, evidence, tiers, Scanner
checks-base       Kotlin/JVM  base-tier checks + the probe interfaces they read
report            Kotlin/JVM  hardening index, verdicts (✓ – ✗ ?), grades, category summaries,
                              Markdown export (later: JSON, diff between scans)
platform-android  Android     probe implementations; the only framework calls for base checks;
                              also the permission overview shown on the Tools screen
app               Android     Compose UI (dashboard, checks, tools, help), registry wiring,
                              settings deep links, report save/share
checks-adb        (later)     Kotlin/JVM checks; probes implemented in platform-android
checks-shizuku    (later)     Android, Shizuku UserService + parsers
```

Check logic never imports `android.*`, so every check is unit-tested on the plain JVM with fakes
(no Robolectric). The cost: a check that needs a new framework call also needs a probe method in
`platform-android`. The JVM modules compile against the JDK, so they could use a `java.*` API
that Android 8.0 lacks (e.g. `LocalDate.ofInstant`, API 34). They apply `com.android.lint` and the
app lints its dependencies (`checkDependencies`) so `NewApi` covers them; this is configured but
not yet proven with a deliberate violation.

## 3. Check contract

```kotlin
interface Check {
    val spec: CheckSpec                                  // id, category, title, severity, explanation,
    suspend fun run(context: ScanContext): Outcome       // remediation, minSdk, requires, timeout
}

sealed interface Reading<out T> { Value | Unsupported | Unavailable }  // what probes return
data class Outcome(status, summary, evidence, escalation: Severity?)  // what checks return
data class Finding(spec, status, severity, summary, evidence, elapsedMillis)  // what reports store
```

- `Status`: PASS, FAIL, UNKNOWN, UNSUPPORTED. `Reading.evaluate {}` maps Unsupported to
  UNSUPPORTED and Unavailable to UNKNOWN, so a check cannot PASS without a value.
- `Evidence(label, value, source, note)`; `Source(method, grant)` names the exact API or command
  and the privilege used.
- Tiers: `requires: Set<Grant>` per check; `requiredTier` is derived. A root tier adds a `Grant`.
- Registry: `baseChecks(probes)`; adding a check is one class plus one line.
- `Scanner`: gates on `minSdk` and grants (UNSUPPORTED, not run), runs the rest concurrently with
  a per-check timeout; exceptions and timeouts become UNKNOWN.

## 4. Scoring

Weights by declared severity: CRITICAL 10, WARNING 5, NOTICE 2, INFO 0. Score = floor(100 ×
passed weight / scored weight), PASS and FAIL only. Any CRITICAL FAIL (including one escalated
by the check) caps it at 40. No scored check means no score, not 0 or 100. The index changes when
more tiers are unlocked, so the UI always shows the tier and counts next to it.

## 5. Open questions for review

1. Application id `io.github.capitan0n.droynis`: cheap to change now, painful after release.
2. Check texts are English Kotlin strings. Move them to resource keys before inviting translators?
3. Patch age thresholds (90 / 365 days) and the escalation mechanism.
4. Weights and the critical cap.
5. Tier-gated checks appear as UNSUPPORTED with "Needs DUMP (ADB tier)", not as a fifth status.
6. A missing setting is UNKNOWN even where AOSP treats "unset" as off (e.g. `adb_enabled`).
   Exception: `show_password` unset is a FAIL, because the framework reads it with a default of
   1 (checked in `TextKeyListener`), i.e. passwords are shown.
7. GPL-3.0-only or GPL-3.0-or-later? The LICENSE file is the same; the source headers and F-Droid
   metadata are not.
8. The Markdown report lists app labels and package names in evidence (accessibility services,
   notification listeners, keyboards, sideloaded apps). Redact them by default, as point 13 says?

## 6. Testing

- Checks: JVM unit tests against fake probes, including threshold boundaries.
- Scanner: virtual-time tests for timeouts and cancellation, plus a real-thread test where a
  check blocks like a hung binder call.
- `platform-android`: instrumented tests run the real probes and all base checks on an emulator;
  a local unit test pins the SDK constants that the JVM modules hard-code.
- `app`: a Compose UI test launches the app, waits for the scan, opens the Checks tab, scrolls to
  every check, opens one and its evidence, and visits the Tools and Help tabs.
- CI on every push: unit tests, lint, release build, and a check that the release APK does not
  request `INTERNET`. The emulator matrix is a manual workflow. API 37 system images use the new
  `37.0` package naming and need cmdline-tools 22+
  ([android-emulator-runner#482](https://github.com/ReactiveCircus/android-emulator-runner/issues/482)).

## 7. Toolchain

AGP 9.3.3, Gradle 9.7.1, Kotlin 2.4.20 (the newest combination Kotlin officially supports),
compileSdk and targetSdk 37, minSdk 26, JDK 17. Release builds drop AGP's dependency-info block
and VCS info for reproducibility; still to verify with a second build and `diffoscope`, in
particular baseline profiles.

## 8. UI

Material 3 with a fixed teal brand scheme (light and dark, user-selectable), large rounded cards
and a bottom navigation bar: Dashboard, Checks, Tools, Help. Status colors never change with the
theme and always come with a glyph and a label: green ✓ passed, yellow – needs attention, red ✗
critical, grey ? unknown and ⃠ not available. Category colors (blue, violet, magenta, green) are
used for category icons only, so they never read as a status. The score ring is colored by the
result (red whenever a critical failure caps it) on a faded track of the same hue.

The UI talks to the platform only through `AppActions` (open Settings, save/share/copy the report,
theme), implemented by `MainActivity`; screens take plain state, which keeps them previewable.
