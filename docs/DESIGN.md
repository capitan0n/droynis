# Droynis design notes

How Droynis fits current Android (API 37, October 2026) and why it works the way it does. What
each check does and when it fails: [CHECKS.md](CHECKS.md). Older, longer notes are in git history.

## 1. Principles

- **Read-only.** Never changes a setting. No `INTERNET` permission: CI fails the build if one appears.
- **No false PASS.** Probes return a `Reading` (Value, Unsupported, Unavailable) and never throw; only
  a Value can pass. Unreadable is UNKNOWN, a missing feature is N/A. A missing setting is UNKNOWN
  unless the framework's default is known.
- **Versions vs. probing.** `SDK_INT` (`CheckSpec.minSdk`, guards in adapters) decides whether an
  API exists; runtime probing handles content: OEM differences, missing keys, `SecurityException`.
- **No identifiers.** No IMEI, serial, phone number, accounts or user names. Values that identify a
  network or computer (DNS, proxies, hosts, Wi-Fi names) are marked `personal`.
- **Pure-Kotlin check logic.** Only `platform/android` calls the framework, so every check is
  unit-tested on the JVM with fakes (no Robolectric). The cost: a new framework call needs a probe.

## 2. Modules

```
core/model        :core-model        JVM      check contract, results, evidence, tiers, Scanner
core/report       :report            JVM      score, verdicts, Markdown/JSON reports, personal-detail hiding
checks/base       :checks-base       JVM      base-tier checks and their probe interfaces
checks/adb        :checks-adb        JVM      ADB-tier checks, dumpsys parsers, CatalogDocTest (CHECKS.md)
checks/shizuku    :checks-shizuku    JVM      Shizuku-tier checks, `PrivilegedShell` probe
checks/root       :checks-root       JVM      root-tier checks, parsers, `RootShellProbe`
platform/android  :platform-android  Android  probe implementations, grant detection, Shizuku client and
                                              its UserService (AIDL), the opt-in root shell
app               :app               Android  Compose UI, registry wiring, Settings links, report export
```

Project paths stay flat (`:checks-adb`) whatever the directory. JVM modules compile against the
JDK, so they apply `com.android.lint` and the app lints dependencies (`checkDependencies`) to catch
`NewApi` (configured, not yet proven with a deliberate violation).

## 3. Check contract

```kotlin
interface Check {
    val spec: CheckSpec                                  // id, category, title, severity, explanation,
    suspend fun run(context: ScanContext): Outcome       // remediation, failsWhen, minSdk, requires, timeout
}
sealed interface Reading<out T> { Value | Unsupported | Unavailable }   // what probes return
data class Outcome(status, summary, evidence, escalation: Severity?)   // what checks return
```

- Status: PASS, FAIL, UNKNOWN, UNSUPPORTED. `Reading.evaluate {}` maps Unavailable to UNKNOWN.
- `Evidence(label, value, source, note)`; `Source(method, grant)` names the exact API or command.
- Tiers: `requires: Set<Grant>` per check. Grants are re-detected every scan, since `pm grant` and
  `pm revoke` apply without a restart.
- `Scanner` gates on `minSdk` and grants, runs checks concurrently off the main thread, each detached
  and racing its timeout: a blocking binder call can't be interrupted, so a hang costs one thread,
  not the scan. Exceptions and timeouts become UNKNOWN.

## 4. Tiers

- **Base:** public APIs. `QUERY_ALL_PACKAGES` is required: without it Android 11+ hides most apps and
  app checks would pass falsely (fine on F-Droid; Google Play restricts it).
- **ADB:** `DUMP` and `PACKAGE_USAGE_STATS`, only grantable with `pm grant`. The Usage access switch
  sets only the app-op; dumpsys services check the permission itself. SELinux still blocks some
  services, and dumpsys output is unversioned OEM text: parse narrowly, keep only parsed fields,
  UNKNOWN on parse failure.
- **Shizuku:** Droynis never sends Shizuku a command. Shizuku runs `ShellService`, a class from
  Droynis' APK, as the shell user in its own process. Its AIDL has one method per read: `settings
  get` (fixed tables, key `[a-z0-9_.-]{1,100}`), `getenforce`, `/proc/cmdline`, `dumpsys` for
  `appops`, `trust`, `wifi`, and `telephony()`. No shell, absolute paths, timeout, output cap;
  dumpsys streams over a pipe. There is no general "run", so even a compromised app process can
  only ask for these reads. `Grant.SHIZUKU` is held only while connected and covers the ADB grants.
  (`Shizuku.newProcess` is private since API 13.1.5, hence the UserService.)
- **Root:** off until the user turns it on, so no unrequested root prompt. One `su` per scan,
  `id -u` must be 0, closed when the scan ends (also on cancel); scans are serialized. Commands are
  constants; each runs as `{ cmd; } </dev/null 2>&1` followed by a random per-session marker and
  the exit code, so output can't end a command early. A timeout kills the shell. Reads go through
  Shizuku when it's connected (fewer rights). Telephony runs in an `app_process` with Droynis' APK
  as class path, the way Shizuku starts its server.

## 5. Platform facts behind the checks

### Device integrity

- **Attestation** (INTG-1040, INTG-1011): own DER parser for KeyDescription (no Bouncy Castle);
  only TEE or StrongBox is trusted. The chain is **not yet verified** against Google's roots (legacy
  RSA, and ECDSA P-384 used alone by RKP devices since April 2026), so it's posture, not proof: the
  verifier runs inside the OS being judged. To do: root check, revocation list (imported through
  SAF, no network), Auditor's (MIT) verified-boot key table, raw chain export for off-device
  verification.
- **Boot properties** (fallback): root can fake "locked" but they don't lie about "unlocked", so on
  a rooted phone "locked" is UNKNOWN. `getprop` runs once per scan (cached 10 s); a property SELinux
  hides is "not visible", never false. `ro.adb.secure=0` makes INTG-1060 CRITICAL.
- **Patch age** (INTG-1010): fixes ship mostly quarterly since mid-2025, so PASS up to 90 days,
  WARNING up to a year, CRITICAL beyond. `SECURITY_PATCH` is self-reported. INTG-1011 judges only
  the vendor/kernel gap (attestation tags 718/719).
- **WebView** (INTG-1070): the provider's `lastUpdateTime`; a system-image date (2009-01-01 from
  reproducible builds) uses `Build.TIME`, and dates before 2017 are placeholders. Chromium majors up
  to 152 (2026-08-25, four-week cadence) give a lower bound on age, so an old version fails even
  with a recent date (/e/OS on a Fairphone 5 shipped 148 in a 43-day-old image).
- **Root** (INTG-1050): heuristic (su paths by existence, root managers and hooking frameworks by
  package). Hidden root (DenyList, Shamiko, KernelSU) isn't detected, and the explanation says so.
- **Advanced Protection** (INTG-1030): INFO, because it blocks unknown-source installs (F-Droid).
  GrapheneOS has no such switch (detected by Vanadium WebView or `app.grapheneos.*`), so N/A there.

### Settings apps can read

- Hidden keys are readable at target 31+ only when marked `@Readable`. Used: notification listeners,
  lock-screen notification keys, lock delay, Wi-Fi/BLE always-scan, `adb_allowed_connection_time`,
  assistant keys. Not readable: `always_on_vpn_app` (Shizuku tier); `enabled_input_methods` beyond
  target 33 (`InputMethodManager` instead).
- Android 17 redacts `adb_enabled` and `development_settings_enabled` to "0" for apps. On API 37+ a
  "0" is UNKNOWN, a "1" still a FAIL. Shizuku reads them unredacted; without it, `USB_STATE` (adb
  function while `connected`) or `adb_wifi_enabled=1` still proves "on".
- Known defaults: `show_password` unset is a FAIL (framework default 1); `adb_allowed_connection_time`
  unset is a PASS (7 days); lock delay unset is UNKNOWN (SystemUI's default is unreadable).

### Access control

- **Lock strength** (ACCS-2007): `getPasswordComplexity()`; LOW (pattern, repetitive PIN) fails.
- **Biometrics** (ACCS-2009): `canAuthenticate` says only that some sensor of a class is enrolled;
  Class 1 and OEM face unlock are invisible. STRONG passes only if one sensor type is declared.
- **Remote lock** (ACCS-2020): find-my services aren't visible to apps. An active admin declaring
  force-lock and wipe-data that answers to the user passes; a preinstalled one (Knox Guard, carrier
  or lender lock) is UNKNOWN. microG takes Play services' name but has no Find Hub.
- **Smart Lock** (ACCS-2101, ADB): `dumpsys trust` for the current user; `trustManaged` or Extend
  Unlock fails. The user name and agents' messages in the dump are never read.
- **Restart** (INTG-1080): `elapsedRealtime()` over 7 days fails (NSA mobile guidance).
- Theft protection switches aren't in the Settings provider, so no check reads them.

### Apps

- **Installer:** system, known store, or sideloaded. A sideloaded holder of accessibility,
  notification access, device admin or SMS/call log access escalates (banking trojans, stalkerware).
  Preinstalled holders are listed, not counted.
- **Special app access** (ADB): `dumpsys appops`; a uid mode overrides package modes, as in
  `AppOpsService.checkOperation`. `cmd appops query-op` was rejected: it misses uid-mode grants such
  as All files access. A line in an unknown shape fails the parse and is quoted in the result.
- **Screen capture** (APPS-4108): PROJECT_MEDIA `allow` skips the consent dialog; only `appops set`
  sets it since Android 10.
- **Play services** (APPS-4014): microG is recognized first (`org.microg.*`, its key), since it can
  spoof Google's. Google's key plus `MATCH_SYSTEM_ONLY` tells a privileged copy (FAIL, INFO) from
  sandboxed Play (PASS).
- Autofill and assistant checks read public or `@Readable` state; Credential Manager providers only
  see what apps request, so they aren't counted. Battery optimization is INFO.

### Network and radios

- **Added system CAs** (NETW-3012): interception-tool subjects; before Android 14, certificates newer
  than `Build.TIME`; mounts over a store directory in `/proc/self/mountinfo` (from 14, the Conscrypt
  APEX). KernelSU's overlayfs leaves no mount, so only the first two signs work there.
- **Proxies** (NETW-3007): every internet network, so a mobile APN proxy counts behind Wi-Fi.
- **2G** (NETW-3010): Android 8–11 read `preferred_network_mode<subId>`. From 12 only
  `DISALLOW_CELLULAR_2G` policy or the privileged allowed-types read (Shizuku or root) decides.
- **SIM PIN, null ciphers, cell alerts** (ACCS-2201, NETW-3202, NETW-3203): need
  `READ_PRIVILEGED_PHONE_STATE`, so `TelephonyReader` calls the `isub` and `phone` AIDL getters as
  shell. Never reads a number, IMSI or ICCID. `dumpsys phone` was rejected (no SIM lock lines on a
  Samsung with Android 11).
- **Wi-Fi MAC** (NETW-3101, ADB): `dumpsys wifi`. A connected MAC without the locally administered
  bit, or a saved network with `macRandomizationSetting=0`, fails. Only the address kind is stored.
  Disconnected is N/A (the factory MAC can linger 30 s after Wi-Fi turns on).
- **Open Wi-Fi auto-join** (NETW-3102, ADB, 12+): open, WEP or Enhanced Open saved networks with
  `allowAutojoin`, ephemeral ones excluded. Names are `personal`; any odd shape is UNKNOWN.
- **Secure NFC** (NETW-3011): NFC off passes. A failing NFC service reads as "off": a rare false
  FAIL, never a false PASS.

### Not done

- Logcat: since Android 13 every session needs a foreground dialog, so interactive only.
- Distribution: Google's developer verification (worldwide in 2027) also blocks F-Droid installs on
  certified phones. Reproducible builds let F-Droid ship the developer's signature if it's registered.

## 6. Scoring and reports

- Weights: CRITICAL 10, WARNING 5, NOTICE 2, INFO 0. Score = floor(100 × passed ÷ scored weight),
  PASS and FAIL only; no scored check means no score. A critical FAIL caps it at 40, so many small
  passes can't hide one critical gap (like SSL Labs' grade caps). The cost is resolution, so
  `uncappedScore` is shown and reported too.
- Muting: the check still runs and keeps its real status, but leaves the index and dashboard
  counts. Never silent: the dashboard counts muted checks and both reports list them.
- Markdown is for people. JSON (`droynis-report`, `schemaVersion` 1, additive fields only) is for
  `diff` and tools: catalog order, stable keys, `null` for unread values.
- Personal details are hidden by default: `personal` evidence wherever it appears, and every IPv4,
  IPv6 and MAC address except "any" and loopback. App names, model and Android version stay.

## 7. UI

- Material 3, teal brand, light and dark. Status colors never change with the theme and always come
  with a glyph and label (✓ – ✗ ? ⃠). Category colors are for icons only.
- Check catalog: one tab per tier with its setup (live grant state, `pm grant`/`pm revoke`
  commands, Shizuku steps, root on/off).
- Search matches word prefixes across id, texts, summary and evidence; it combines with filters.
- The network inspector hides addresses until tapped, and forgets the choice on restart.
- Screens take plain state and reach the platform only through `AppActions` (`MainActivity`).

## 8. Testing and build

- Checks and parsers: JVM tests with fakes, threshold boundaries and mutated dumpsys output that
  must fail the parse. Scanner: virtual-time tests plus a real thread blocking like a hung binder.
- `CatalogDocTest` generates CHECKS.md; `check` fails while it's stale
  (`UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test` rewrites it).
- Instrumented (manual workflow, API 26–37 emulators): real probes, root off by default, a Compose
  walkthrough of every screen. Shizuku and `su` sessions need a real device.
- CI: unit tests, lint, builds and the no-`INTERNET` gate. A tag builds the signed, attested release
  and checks the build is reproducible.
- Versions: `gradle/libs.versions.toml`. JDK 21 (bytecode 17), minSdk 26, compile and target 37.
  Release builds drop dependency and VCS info so they reproduce.

## 9. Open questions

1. Move check texts to string resources for translators?
2. Patch age thresholds (90 / 365 days) and escalation.
3. Weights and the critical cap.
4. Hide user-installed app names in reports too?
5. Muting a critical failure lifts the cap: flag it beyond the muted count?

Droynis is independent of Lynis and CISOfy and shares no code with Lynis; it borrows only the idea
of a readable audit with a hardening score.
