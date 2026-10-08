# Droynis design notes

Status: 54 checks in four tiers (listed in [CHECKS.md](CHECKS.md)) and a Compose UI with
dashboard, checks, tools and help screens. This file records how the brief maps onto current
Android (API 37, October 2026) and the decisions taken so far.

## 1. Brief review: what does not hold on current Android

| # | Brief says | Reality | Decision |
|---|---|---|---|
| 1 | Verify boot state with on-device key attestation, like Auditor | The chain is signed in hardware, but the code that verifies it runs inside the OS being judged; a rooted OS can hook the verifier. Auditor is trustworthy because a *second* device or server verifies and pins. | Present it as posture ("self-attested"), never as proof. Allow exporting the raw chain for off-device verification. Trust both Google roots: the legacy RSA root and the ECDSA P-384 root that RKP devices use exclusively since April 2026. Reuse Auditor's (MIT) verified-boot key table and keep it current. |
| 2 | List apps with permissions, accessibility, admins… | Since API 30 package visibility hides most apps unless the app holds `QUERY_ALL_PACKAGES`. Without it, invisible apps produce false PASSes. | Declare `QUERY_ALL_PACKAGES` (fine on F-Droid; Play restricts it). |
| 3 | Base tier reports overlay, usage access, install-unknown, all-files, notification listener, VPN for every app | No uniform public API. These are app-ops or Settings keys of *other* apps: reading a foreign app-op mode via `AppOpsManager.unsafeCheckOpNoThrow` is version-dependent and visibility-filtered, some op strings are hidden (`android:request_install_packages`, `android:manage_external_storage`), and notification listeners / always-on VPN live in hidden `Settings.Secure` keys that apps targeting API 31+ may read only if the platform marks them `@Readable` (otherwise `SecurityException`). Which app owns the active VPN is shown only to that app. | Best effort in base tier, UNKNOWN on any failure. Authoritative via `dumpsys appops` (ADB tier, or Shizuku) for the app-op switches and `settings get` through Shizuku for hidden keys. Public and reliable: accessibility (`ENABLED_ACCESSIBILITY_SERVICES`), device admins (`getActiveAdmins`), default SMS/dialer, runtime permissions, debuggable/targetSdk, installer. Checked against the Android 16 and 17 framework: `enabled_notification_listeners` and both `lock_screen_*` notification keys carry `@Readable` and are used; `always_on_vpn_app` does not, `enabled_input_methods` only up to target API 33 (keyboards come from `InputMethodManager` instead). |
| 4 | Probe at runtime instead of branching on Android version | Calling an API newer than the device throws `NoSuchMethodError`, and lint's `NewApi` fails the build without an `SDK_INT` guard. | Version checks decide *whether an API exists* (`CheckSpec.minSdk`, `SDK_INT` guards in adapters). Runtime probing handles *content*: missing settings, OEM differences, `SecurityException`. Every probe returns a `Reading` instead of throwing. |
| 5 | `PACKAGE_USAGE_STATS` is an ADB grant | Settings › Usage access sets only the app-op, which is enough for `UsageStatsManager`. dumpsys services that show per-app data (`DumpUtils.checkUsageStatsPermission`, Android 17) also require the permission itself, which only `pm grant` gives. | `Grant.PACKAGE_USAGE_STATS` means the permission (ADB tier). A future `UsageStatsManager` check would add a base-tier usage-access grant. |
| 6 | `READ_LOGS` grant survives reboots and unlocks logcat | Since Android 13 every logcat session also needs a per-session "Allow access to all device logs?" dialog, shown only while the app is in the foreground. SELinux denials are noisy on production builds. | Logcat scan is interactive only. For crash loops, evaluate `DropBoxManager` (`READ_LOGS` + usage access) instead of parsing logcat. |
| 7 | `DUMP` unlocks live dumpsys | It does, but SELinux still blocks `untrusted_app` from some services, and dumpsys output is unversioned, OEM-specific text that can include account names. | Parse narrowly, store only parsed fields as evidence, UNKNOWN on parse failure. `dumpsys appops` (APPS-4101) was checked against AppOpsService in Android 17: it needs DUMP and the `PACKAGE_USAGE_STATS` permission; `VpnManagerService` prints no lockdown state; the adb service is not visible to apps. |
| 8 | Shizuku, and "no non-SDK interfaces" | Typical Shizuku code wraps hidden AIDL interfaces (`IAppOpsService`…), which is non-SDK by definition. `Shizuku.newProcess` is private since Shizuku-API 13.1.5. | Use a Shizuku `UserService` (our code running as shell, UID 2000) that runs a fixed allowlist of read-only commands and returns text over our own AIDL. |
| 9 | A crashing or hanging check yields UNKNOWN | Coroutine timeouts only fire at suspension points; a blocking binder call cannot be interrupted. Native crashes and OOM kill the process. | Implemented: each check runs detached and races a timeout, so a hang costs one thread, not the scan. A separate scanner process is not worth it for v1. |
| 10 | Network off by default, revocation list opt-in | `INTERNET` is granted at install. Once declared, "off by default" cannot be verified from the manifest. | Ship without `INTERNET` (CI fails the build otherwise). Import the revocation list JSON through the Storage Access Framework, or provide a separate online flavor. |
| 11 | Distribute via F-Droid | Google's developer verification blocks apps from unregistered developers on certified devices (enforced since 2026-09-30 in Brazil, Indonesia, Singapore and Thailand; worldwide in 2027), F-Droid installs included. | A distribution decision, not a code one. Reproducible builds let F-Droid ship *your* signature, so the same key works if you choose to register. |
| 12 | Security patch age | Since mid-2025 most fixes ship in quarterly bulletins (March, June, September, December); monthly ones can be empty. `SECURITY_PATCH` is self-reported and vendors have over-claimed it before. | PASS up to 90 days, WARNING up to a year, CRITICAL beyond. Cross-check with the attested `osPatchLevel` once attestation lands. |
| 13 | Reports exclude IMEI, serial, phone number, account names | The base tier cannot read those anyway: IMEI and serial are privileged since API 29, and phone number and accounts need permissions Droynis does not request. The real leaks are the installed-app list (health, religion, politics…), CA certificate subjects (employer), Private DNS hostname and raw dumpsys text. | Export redacted by default (package names omitted or hashed); raw only on explicit choice. |
| 14 | Advanced Protection (API 36+) | Readable with the normal permission `QUERY_ADVANCED_PROTECTION_MODE`. It also blocks installs from unknown sources, which conflicts with F-Droid users. | INFO (no score impact), with that trade-off in the remediation text. |
| 15 | Developer options and USB debugging are plain public settings | Android 17 annotates `adb_enabled` and `development_settings_enabled` with `@Readable(redactedValue = "0")`: behind the platform flag `enable_redacted_value_for_readable`, every app with UID ≥ 10000 reads "0" whatever the real state, at any target SDK. The mechanism is absent from Android 16. `adb_wifi_enabled` is not redacted. | On API 37+ a "0" is UNKNOWN ("can't be verified"), never PASS; a "1" is still a real FAIL. With Shizuku connected, these two keys (and any key the app is denied) are read again with `settings get` as the shell user, which is never redacted; a reading whose `Source` carries the SHIZUKU grant is trusted. |

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
- **WebView** (INTG-1070): the provider package's `lastUpdateTime`. A system WebView that was never
  updated on its own (ROMs that ship it with the OS) reports the file time from the system image,
  which reproducible builds fix at 2009-01-01; there `Build.TIME`, the system image's build time,
  is its date instead, and the result says it came with a system update.
- **System properties** come from running `/system/bin/getprop` once per scan (cached 10 s).
  SELinux filters what an app may read; a missing property is "not visible", never "false".
  `sys.oem_unlock_allowed` is not readable on every device, so OEM unlocking can be UNKNOWN.
- **Root** (INTG-1050) is a heuristic: known su paths (existence only; Droynis never runs su) and
  root managers or hooking frameworks by package name. Hidden root (DenyList, Shamiko, KernelSU)
  is not detected, and the explanation says so.
- **Location and scanning** (NETW-3008/3009): `LocationManager.isLocationEnabled()` (API 28+,
  `location_mode` before). `wifi_scan_always_enabled` and `ble_scan_always_enabled` are hidden or
  system API constants, but Android 17 marks both `@Readable`, so they are read by name; where a
  release does not, the read fails and the check is UNKNOWN.
- **Lock delay** (ACCS-2006): `lock_screen_lock_after_timeout` is `@Readable` in Android 17. When it
  was never set, SystemUI applies its own default (5 s in AOSP) that apps can't read, so unset is
  UNKNOWN, not PASS. "Power button instantly locks" lives in LockSettings and is unreadable.
- **Remote lock** (ACCS-2020): whether Find Hub, Samsung Find My Mobile or another vendor service is
  on is not visible to apps, and those services need no device admin. `hasGrantedPolicy()` answers
  only the admin itself in Android 17, so Droynis parses each active admin's declared policies
  (`DeviceAdminInfo`): an admin that declares both force-lock and wipe-data, and is not just a work
  profile, is a PASS when it answers to the user: the device owner, a known anti-theft service, or
  an app the user installed. A preinstalled admin with those powers (Samsung's Knox Guard, a
  carrier's or lender's lock) may answer to someone else, so on its own it gives UNKNOWN, never
  PASS. A known service without such an admin is UNKNOWN; nothing at all is a FAIL.
  The theft protection switches (Theft Detection Lock, Offline Device Lock, Identity Check) are not
  in the Android 17 Settings provider (only Identity Check promo flags are), so no check reads them.
- **Lock strength** (ACCS-2007): `KeyguardManager.getPasswordComplexity()` (API 29+). LOW, a
  pattern or a PIN with repeating or ordered digits, is a FAIL; MEDIUM and HIGH pass; no lock is
  N/A here because ACCS-2001 already fails it.
- **SMS and call log** (APPS-4008): apps granted READ_SMS or RECEIVE_SMS, or READ_CALL_LOG, from
  `PackageManager` (granted flags, not just requested). The default SMS app is expected to hold the
  SMS ones and the default phone app the call log; preinstalled apps are listed, not counted.
- **Who installed an app**: system apps came with the phone; an installer on the known store list
  is an app store; anything else, including the package installer, is sideloaded. For
  accessibility services, notification access, device admins and SMS or call log access, a
  sideloaded holder raises the FAIL to WARNING, since that is how banking trojans and stalkerware
  arrive. Preinstalled notification listeners and device admins are listed but not counted.

## 2. Modules

```
Directory         Gradle project     Kind        Contents
core/model        :core-model        Kotlin/JVM  Check contract, results, evidence, tiers, Scanner
core/report       :report            Kotlin/JVM  hardening index, verdicts (✓ – ✗ ?), grades, category
                                                 summaries, Markdown and JSON reports, hiding personal details
checks/base       :checks-base       Kotlin/JVM  base-tier checks + the probe interfaces they read
checks/adb        :checks-adb        Kotlin/JVM  ADB-tier checks, dumpsys parsers and the `Dumpsys` probe they
                                                 read; CatalogDocTest, which keeps docs/CHECKS.md in sync
checks/shizuku    :checks-shizuku    Kotlin/JVM  Shizuku-tier checks and the `PrivilegedShell` probe they read
checks/root       :checks-root       Kotlin/JVM  root-tier checks, their parsers and the `RootShellProbe` they read
platform/android  :platform-android  Android     probe implementations; the only framework calls for checks;
                                                 grant detection; the permission overview on the Tools screen;
                                                 the Shizuku client and its read-only UserService (AIDL);
                                                 the opt-in root shell
app               :app               Android     Compose UI (dashboard, checks, tools, help), registry
                                                 wiring, settings deep links, report save/share
```

Directories group modules by layer; Gradle project paths stay flat (settings.gradle.kts maps each one),
so commands such as `./gradlew :checks-adb:test` don't depend on where a module lives.

### Shizuku

Droynis never sends Shizuku a command. Shizuku runs `ShellService`, a class from Droynis' own APK,
in a separate process as the shell user (root if Shizuku was started with root), and hands its
binder to the app. Its AIDL interface (`IShellService`) has one method per read: `settings get`
(table from a fixed set, key matched against `[a-z0-9_.-]`), `getenforce`, `dumpsys` for an
allowlist of services (`appops`, `trust`), and `telephony()`, which runs `TelephonyReader`: a fixed
set of telephony getters (below). Commands run without a shell, with absolute paths, a
timeout and an output cap; `dumpsys` streams through a pipe because its output can exceed one
binder call.
There is no general "run" method, so even a compromised app process can only ask for these reads.
The service is not a daemon: Shizuku stops it when the app unbinds or dies. Transaction 16777115
(`destroy`) is reserved by Shizuku and exits the process.

`Grant.SHIZUKU` is held only while that shell is connected, not merely when Shizuku runs. Its shell
holds every permission adb can grant, so `Capabilities.has` lets SHIZUKU cover the ADB-tier
grants, and `dumpsys` falls back to the shell when the app itself lacks DUMP and
PACKAGE_USAGE_STATS. A scan connects the shell first (up to 10 s), and the app scans again when
Shizuku starts or allows Droynis.

### Root

Root is off until the user turns it on in the Root tab, so a rooted phone never sees a root
manager prompt it didn't ask for. When on, each scan runs `su` once (the root manager asks the
first time), confirms `id -u` is 0, runs its reads, and closes the shell when the scan ends, even a
cancelled one; scans are serialized so one can't close another's shell. Commands are constants in
`RootShell`; the only arguments, a settings table and key, are checked like in `ShellService`. Each
command runs as `{ cmd; } </dev/null 2>&1` followed by a line with a random per-session marker and
the exit code, so no output can end a command early and no command can read the session's stdin.
A command that doesn't answer in time kills the shell.

`Grant.ROOT` is held while root is on and the last shell ran as root. Root covers the Shizuku and
ADB grants (`Capabilities.has`); reads go through Shizuku while it is connected (fewer rights) and
through root otherwise. Root-only checks: computers trusted for USB debugging (`adb_keys`, with the
MD5 fingerprint the "Allow USB debugging?" dialog shows), apps with root (Magisk's `policies` table
through `magisk --sqlite`, whose `col=value|…` rows and Query/Deny/Allow/Restrict values were checked
in Magisk's source; KernelSU and APatch store theirs in their own formats, so the check is N/A
there), root modules in `/data/adb/modules` (shared by all three managers; INFO, not scored), and
apps listening on the network (`/proc/net/{tcp,udp}{,6}`: TCP in LISTEN and unconnected UDP on a
port below 32768, on any address but loopback; system uids and system apps are listed, not counted).

### Mobile network and SIM

Apps get no permission-free way to read the SIM PIN lock or, from Android 12, the Allow 2G switch:
`TelephonyManager.isIccLockEnabled` (Android 11+, system API) and `getAllowedNetworkTypesForReason`
(Android 12+) need READ_PRIVILEGED_PHONE_STATE, which the shell user holds. `TelephonyReader` calls
them through the `isub` and `phone` services' AIDL interfaces for each visible active subscription,
plus `getSlotIndex`, and prints one line per SIM; only getters, no state. It runs in Droynis'
Shizuku shell, or, with root only, in an `app_process` the root shell starts with Droynis' APK as
class path (as Shizuku and scrcpy start their own code; hidden-API checks don't apply there). The
APK path is Android's and is checked against a strict pattern. One read serves both checks per scan.
`dumpsys phone` was rejected: on a Samsung Android 11 it holds no SIM lock lines.

- **2G** (NETW-3010, base tier): on Android 8–11 the per-SIM `preferred_network_mode<subId>` setting
  decides, readable by any app (checked against SettingsProvider in Android 11); unset means
  `ro.telephony.default_network`. Modes follow `RILConstants`, with CDMA 1x counted as 2G like
  Android's `NETWORK_CLASS_BITMASK_2G`; an unknown vendor mode is UNKNOWN. From Android 12 that
  setting is no longer the source of truth, so it is never used there: device policy
  (`DISALLOW_CELLULAR_2G`, Android 14+, set by Advanced Protection) passes on its own, else the
  privileged read ANDs every reason's allowed types (network mode, power, carrier, Allow 2G, user
  restriction), like Settings shows the switch; without Shizuku or root it is UNKNOWN.
- **SIM PIN** (ACCS-2201, Shizuku tier, Android 11+): FAIL for any SIM in use with its lock off.
  SIMs in use come from `getSimState` per slot and `SubscriptionManager.getSubscriptionIds`, which
  need no permission; Droynis never reads a number, IMSI or ICCID.

### Special app access

Settings › Apps › Special app access switches are app-ops. `dumpsys appops` prints a uid's mode
(only when it differs from the op's default) and each package's own mode; like
`AppOpsService.checkOperation`, a uid mode decides for every package of the uid, otherwise the
package mode does. `cmd appops query-op` was rejected because it reports package modes only, and
All files access is set as a uid mode, so it would miss it and pass falsely. Covered (ADB tier,
so Shizuku too): display over other apps, all files access, install unknown apps, usage access,
and, as INFO (listed, not scored), modify system settings and media management. App stores are
expected to install apps; system apps and Droynis itself are listed but not counted. Not covered:
premium SMS (not an app-op), do not disturb access (a Settings key), and low-risk switches such as
picture-in-picture, alarms or unrestricted data. Limitation: an app holding the access through a
permission granted at install (target SDK below 23) and a default mode is not seen.

Android 12 and later put the per-app part under an `AppOps Uid Op State` header; Android 11 and
older start it with the first `Uid` line, so the parser starts there when the header is missing.
A line about a requested op in an unknown shape fails the parse rather than hide a grant, and the
failure quotes the first such line (up to 100 characters), so a shared report is enough to fix it.

### Patch levels and proxies

INTG-1011 compares the vendor and boot (kernel) patch levels with Android's. Both come from the
same hardware attestation as the bootloader check (tags 718 and 719, Keymaster 4 and later; one key
per app run, since what it attests changes only with a reboot), with `ro.vendor.build.security_patch`
as the vendor fallback; a software attestation is ignored. Only the gap counts (over 90 days, critical beyond a year): an old stock
phone is INTG-1010's finding, not this one's. The modem firmware version (`gsm.version.baseband`) is
evidence only: nothing public maps it to fixes.

NETW-3007 reads every connected network with the internet capability (`getAllNetworks`), so a
proxy set in the mobile data APN counts while Wi-Fi is the default network. A proxy the default
network reports but no network carries itself is a global proxy. MMS and IMS networks are skipped.

### Smart Lock

ACCS-2101 (ADB tier, DUMP only) reads `dumpsys trust`: for the current user, whether a trust agent
manages trust (`trustManaged`) or Extend Unlock (active unlock) runs, and which agents are enabled.
Either one on is a FAIL, because the phone may stay unlocked without the PIN. The dump also holds
the user's name and each agent's own message (for example the name of a trusted place or device);
Droynis reads neither into the report. Only the per-user part is read, up to the event log.

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
- Registry: `baseChecks(probes)` and `adbChecks(probes)`; adding a check is one class plus one line.
- Grants are detected for every scan (`checkSelfPermission`, plus the usage-stats app-op not
  being denied), because `pm grant` and `pm revoke` take effect without a restart.
- `Scanner`: gates on `minSdk` and grants (UNSUPPORTED, not run), runs the rest concurrently with
  a per-check timeout; exceptions and timeouts become UNKNOWN. All of it runs off the collecting
  thread, so a busy main thread neither delays results nor counts in a check's `elapsedMillis`.

## 4. Scoring

Weights by declared severity: CRITICAL 10, WARNING 5, NOTICE 2, INFO 0. Score = floor(100 ×
passed weight / scored weight), PASS and FAIL only. Any CRITICAL FAIL (including one escalated
by the check) caps it at 40. No scored check means no score, not 0 or 100. The index changes when
more tiers are unlocked, so the UI always shows the tier and counts next to it.

### Muting

The user can mute a check whose finding they cannot act on (security patch age is the usual
case: only the manufacturer ships patches). A muted check still runs and keeps its real status;
it is only left out of the index (score, cap, counts) and of the dashboard counts and issue
lists. Muting never turns a FAIL into a PASS, and it is never silent: the dashboard shows how many
checks are muted, and both reports list them (`score.muted`, `"muted": true` per finding in JSON).
Muted ids are stored on the device (`SharedPreferences`) and the index is recomputed on the spot,
without a new scan. Ids that no longer exist are dropped when read. The Checks tab's Muted filter offers
Unmute all, after a confirmation, since re-muting means opening each check again.

### Why the critical cap stays

A weighted average lets many small passes hide one critical gap: 29 passes and no screen lock would
otherwise score above 90. The cap makes the score follow the weakest link, as SSL Labs does with
its grade caps. Its cost is lost resolution: fixes elsewhere no longer move the capped number, and
a heuristic false positive (root detection) hurts a lot. So `HardeningIndex.uncappedScore` is
kept, shown next to a capped score and written to both reports.

### Reports

Markdown is for people. JSON (`JsonReport`, `"schema": "droynis-report"`, `schemaVersion` 1) is for
diffing and tools: findings in catalog order, stable keys, two-space indentation, `null` for
values that could not be read. Fields added since (`scan.grants`, `score.muted`, `muted` per
finding) are additive, so the schema version stays 1; `verdicts` and `score` leave muted checks
out. Both contain only scan results and the device facts passed in.

Reports are made to be shared, so by default they leave out personal details (`PersonalDetails`):
evidence a check marks `personal` (DNS servers, proxies, the Private DNS host, which can carry a
NextDNS-style profile ID, and computers trusted for USB debugging), those values wherever a summary
repeats them, and every IPv4, IPv6 and MAC address in the text, except "any address" and loopback.
App names, the model and the Android version stay: findings are about them and they don't single
out one phone. One menu switch, saved on the device, covers saving, sharing and copying; JSON says
`"personalDetails": "hidden"` or `"included"` and marks `personal` evidence either way.

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
8. Reports hide addresses, DNS and proxy hosts and trusted computers by default, but keep app
   labels and package names, which the findings are about. Hide user-installed apps too?
9. Muting is allowed for every check, critical ones included, and lifts the cap. Should a muted
   critical failure still be flagged on the dashboard beyond the muted count?

## 6. Testing

- Checks: JVM unit tests against fake probes, including threshold boundaries.
- Scanner: virtual-time tests for timeouts and cancellation, plus a real-thread test where a
  check blocks like a hung binder call.
- docs/CHECKS.md is generated from the check specs by `CatalogDocTest` (in `checks-adb`, the
  module that sees every registry); `check` fails while the file is stale, and
  `UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test` rewrites it. Every spec must set `failsWhen`.
- dumpsys parsers: JVM tests on output shaped like the Android 17 source, plus mutations (an
  `Access:` line in another shape, an orphan line, no records) that must fail the parse.
- `platform-android`: instrumented tests run the real probes and all checks on an emulator
  (ADB-tier ones are gated to N/A without grants, and dumpsys must refuse rather than answer);
  a local unit test pins the SDK constants that the JVM modules hard-code.
- Shizuku: the shell, the binder and Shizuku itself need a device with Shizuku; instrumented tests
  only check that without it the shell readings are Unavailable and SHIZUKU is not granted.
- Root: the parsers (modules, Magisk policies, `/proc/net`, `adb_keys`) are JVM-tested; the `su`
  session needs a rooted device. Instrumented tests check that root is off by default and that
  nothing runs `su` then.
- `app`: a Compose UI test launches the app, waits for the scan, opens the Checks tab, scrolls to
  every check, opens one and its evidence, visits the Tools, Help and About pages and every
  catalog tab (including the adb commands), and mutes and unmutes a check.
- CI on pushes to main and pull requests: unit tests, lint, debug and release builds, and a gate
  that the release APK does not request `INTERNET`; the debug APK is kept as an artifact. A tag
  runs the release workflow (signed, attested APK; [RELEASING.md](RELEASING.md)) and the
  reproducible-build check. The emulator matrix is a manual workflow; API 37 system images use the
  `37.0` package naming and need cmdline-tools 22+
  ([android-emulator-runner#482](https://github.com/ReactiveCircus/android-emulator-runner/issues/482)).

## 7. Toolchain

AGP 9.3.3, Gradle 9.7.1, Kotlin 2.4.20 (the newest combination Kotlin officially supports),
compileSdk and targetSdk 37, minSdk 26, JDK 17. Release builds drop AGP's dependency-info block
and VCS info for reproducibility; the reproducible-build workflow builds each tag twice, from two
directories, and compares the APKs (baseline profiles are the usual suspect if they ever differ).

## 8. UI

Material 3 with a fixed teal brand scheme (light and dark, user-selectable), large rounded cards
and a bottom navigation bar: Dashboard, Checks, Tools, Help. Status colors never change with the
theme and always come with a glyph and a label: green ✓ passed, yellow – needs attention, red ✗
critical, grey ? unknown and ⃠ not available. Category colors (blue, violet, magenta, green) are
used for category icons only, so they never read as a status. The score ring is colored by the
result (red whenever a critical failure caps it) on a faded track of the same hue.

The check catalog (⋮ menu, or a link at the top of Help) lists every check in one tab per tier:
Base, ADB, Shizuku, Root. Each tab opens with what the tier is and how to set it up; the ADB tab
lists each grant as held or not (read live), the exact `pm grant` commands, and `pm revoke`
commands once something is granted. The Shizuku tab shows three steps (Shizuku running, Droynis
allowed, shell connected) and one button for the next step: get Shizuku, open it, or allow access.
The Root tab shows the root manager it can see and whether root is on, with Allow root access,
Try again or Turn off root tier.
Tier-gated checks show "Needs the ADB tier" with a link to that tab. Help keeps only the legend, the score, privacy and the FAQ.

The Checks tab has a search field above the filters. Every word must start a word somewhere in
the check's id, title, explanation, fix, failure rule or category, or, after a scan, in its
summary and evidence, so "sms" finds the SMS check and the two whose texts mention SMS codes, and
an app's name finds the checks that named it; "pin" does not match "keeping", and hyphens are
optional ("wifi" finds "Wi-Fi"). The search combines with the verdict, category and tier filters,
the verdict chips count within it, and the dashboard's links clear it.

The network inspector on the Tools tab shows IP addresses, DNS servers and the HTTP proxy as dots
until the eye in its header is tapped, so a screenshot gives none of them away. The choice is not
stored: every new start of the app hides them again.

The UI talks to the platform only through `AppActions` (open Settings, save/share/copy the report,
theme), implemented by `MainActivity`; screens take plain state, which keeps them previewable.

## 9. Name and credit

Droynis is an independent project, not affiliated with, endorsed by or connected to Lynis or
CISOfy, and it shares no code with Lynis. Lynis inspired only the idea: a readable audit that
explains each finding and sums the result up in a hardening score. The About page, the Help FAQ
and the README say so.
