# Droynis design notes

Why Droynis works the way it does. The checks themselves are listed in [CHECKS.md](CHECKS.md);
how each one reads its value is in the KDoc of its class.

## Principles

- **Read-only.** No check changes a setting. Shizuku and root run a fixed list of read commands.
- **No network.** The APK has no `INTERNET` permission; CI fails the build if it ever does. Data
  that would normally be downloaded, such as the stalkerware list, ships inside the app.
- **Never a false PASS.** A check passes only on a value it read. A value it can't read is UNKNOWN,
  a feature the phone lacks is UNSUPPORTED (N/A). Both are left out of the score.
- **No identifiers.** No IMEI, serial, phone number or account names in evidence. Values that point
  to a network or a computer (DNS, proxies, Wi-Fi names, trusted computers) are marked `personal`
  and hidden in shared reports by default.
- **Visible apps.** Droynis declares `QUERY_ALL_PACKAGES`: without it, Android hides most apps from
  it, and checks that list apps would pass falsely. F-Droid allows it; Google Play restricts it.

## What Android allows

| Limit | What Droynis does |
|---|---|
| Key attestation is signed in hardware, but verified by the OS being judged. A rooted OS can fake the result. | Bootloader and patch checks present it as a self-check, not proof. Only TEE or StrongBox attestations count; without them, `ro.boot.*` properties are a fallback, and a "locked" on a rooted phone is UNKNOWN. |
| Many settings are hidden from apps. From Android 12 apps may read only keys marked `@Readable`. | Readable keys are read in the base tier. Others (always-on VPN, passkey providers, clipboard alerts, lock screen controls) are in the Shizuku tier, read with `settings get` as the shell user. |
| Android 17 makes `adb_enabled` and `development_settings_enabled` always read "0" for apps. | On Android 17 a "0" is UNKNOWN; a "1", or the `adb` USB function while connected, still fails. Shizuku reads the real value. |
| `dumpsys` (app-ops, Wi-Fi, trust agents, services) needs `DUMP` and `PACKAGE_USAGE_STATS`, which only adb can grant. Its output is unversioned text. | The ADB tier. Parsers read only the fields they need, store only parsed values, and fail to UNKNOWN on any line they don't recognize. |
| Shizuku's usual API wraps hidden interfaces. | Droynis runs its own `ShellService` through Shizuku, with one AIDL method per allowed read and no general "run" method. |
| An app sees only the user or profile it runs in. | APPS-4017 says so: it counts the other profiles of this user (work profile, Private Space), which `UserManager.getUserProfiles()` tells any app, and never passes on what it can't see. |
| `isAutoRevokeWhitelisted(package)` answers only the installer or a privileged app. | "Pause app activity if unused" is read in the ADB tier instead (APPS-4109): its app-op is allowed by default, so the exempt apps are the ones set to `ignore`. |
| Termux's `allow-external-apps` and Tasker's Allow External Access live in those apps' private storage. | APPS-4019 reads only who holds their permissions, so a listed app *may* run commands. |
| Premium SMS access is kept in `/data/misc/sms`, which only the phone service and root can read. | APPS-4303 is in the root tier; the root command converts Android 12's binary XML back to text with `abx2xml`. |
| Quick Share (Nearby Share) keeps its visibility in Google Play services' private files, whose keys and numbers Google doesn't document. Samsung's Quick Share app keeps its own. | NETW-3302 is in the root tier and reads `nearbysharing*.xml` in Play services' `shared_prefs`. It takes only what holds in every known version: 4, or the name `EVERYONE`, is Everyone, and 1–3 never are. Any other value, settings that disagree, a cut file or a Samsung phone where Google's setting isn't Everyone is UNKNOWN. |
| No API says whether a chip has a known hardware flaw, and phones before Android 12 don't name their chip (`Build.SOC_MODEL`). | INTG-1013 reads the chip model, `ro.board.platform`, a few vendor chip properties and chip-shaped words in `Build.HARDWARE` and `Build.BOARD`. A Qualcomm platform name several chips share (`msm8916`) is UNKNOWN, and a phone that names no chip is UNKNOWN. |
| `FEATURE_STRONGBOX_KEYSTORE` is only what the phone declares. | INTG-1021 fails when the feature is missing and passes only when a key made with `setIsStrongBoxBacked` is attested at StrongBox level; anything in between is UNKNOWN. |
| A saved Wi-Fi network doesn't record which cipher its access point uses. | NETW-3105 fails only on WEP, which has its own security type. WPA with TKIP shares a type with WPA2 and is not judged. |
| An app's network security config is private to it. | APPS-4018 reads only the manifest's cleartext flag on apps that hold INTERNET: a sign in both directions, so information only. |
| A blocking binder call can't be interrupted. | Each check runs detached and races a timeout: a hang costs one thread, not the scan. |
| Calling an API newer than the phone crashes. | `CheckSpec.minSdk` decides whether a check runs; runtime probing handles missing settings and OEM differences. Probes return a `Reading`, never throw. |

## Modules

| Directory | Kind | Contents |
|---|---|---|
| `core/model` | Kotlin/JVM | Check contract, results, evidence, tiers, `Scanner` |
| `core/report` | Kotlin/JVM | Score, verdicts, Markdown and JSON reports, hiding personal details |
| `checks/base` | Kotlin/JVM | Base-tier checks and the probe interfaces they read |
| `checks/adb` | Kotlin/JVM | ADB-tier checks, `dumpsys` parsers, `CatalogDocTest` (generates CHECKS.md) |
| `checks/shizuku` | Kotlin/JVM | Shizuku-tier checks |
| `checks/root` | Kotlin/JVM | Root-tier checks and their parsers |
| `platform/android` | Android | Probe implementations (the only framework calls), the Shizuku service, the root shell |
| `app` | Android | Compose UI, Settings links, reports, scheduled scans |

Check logic never imports `android.*`, so every check is unit-tested on the plain JVM with fake
probes. The cost: a check that needs a new framework call also needs a probe method in
`platform/android`. Gradle project paths stay flat (`:checks-adb`) whatever the directory.

## Privileged reads

**Shizuku.** Droynis never sends Shizuku a command. Shizuku starts `ShellService`, a class from
Droynis' own APK, as the shell user. Its methods: `settings get` (fixed tables, key checked against
`[a-z0-9_.-]`), `getenforce`, `dumpsys` for a fixed list of services with fixed arguments, a
fixed set of telephony getters (SIM PIN lock, Allow 2G, null-cipher and identifier-disclosure
settings), and the usage history since a given time, returned as one count per app (SUSP-5003, so
Droynis needs no Usage access of its own and never grants itself any). Commands run without a
shell, with absolute paths, a timeout and an output cap. The
`SHIZUKU` grant is held only while that service is connected, and it covers the ADB-tier checks.

**Root.** Off until the user turns it on. Each scan opens one `su` session, checks `id -u` is 0,
runs constant commands and closes it when the scan ends. Every command is followed by a random
per-session marker and its exit code, so no output can end a command early. A command that doesn't
answer in time kills the shell. Root covers the Shizuku and ADB checks; reads go through Shizuku
when it is connected, since it has fewer rights.

## Check contract

```kotlin
interface Check {
    val spec: CheckSpec                                  // id, category, title, severity, explanation,
    suspend fun run(context: ScanContext): Outcome       // fix, minSdk, required grants, timeout, failsWhen
}
sealed interface Reading<out T> { Value | Unsupported | Unavailable }  // what probes return
data class Outcome(status, summary, evidence, escalation: Severity?)  // what checks return
```

- Status: PASS, FAIL, UNKNOWN, UNSUPPORTED. Unsupported readings map to UNSUPPORTED and unavailable
  ones to UNKNOWN, so a check can't pass without a value.
- `Evidence(label, value, source, note)`, where `Source` names the exact API or command and the
  privilege used.
- A check's tier comes from the grants it requires. Grants are detected at every scan, because
  `pm grant` and `pm revoke` take effect without a restart.
- `Scanner` skips checks the phone or the tier can't run (UNSUPPORTED), runs the rest concurrently,
  and turns exceptions and timeouts into UNKNOWN.
- Ids are `AREA-NNNN` and never reused. A moved check keeps its old id in `CheckSpec.RENAMED`, so
  mutes follow it.

## Score

Weights: critical 10, warning 5, notice 2, info 0. Score = passed weight ÷ scored weight × 100,
counting only PASS and FAIL. Any critical failure caps it at 40, so many small passes can't hide one
critical gap (29 passes and no screen lock would otherwise score above 90). The cost is that fixes
elsewhere stop moving a capped score, so the uncapped score is shown next to it and kept in reports.
No scored check means no score, not 0 or 100.

**Muting** leaves a check out of the score and counts, never turns a FAIL into a PASS, and is never
silent: the dashboard counts muted checks and reports list them. It's for findings the user can't
act on, such as a patch only the maker can ship.

**Trusted apps.** Some apps need a lot of access on purpose, such as a watch app that reads
notifications and SMS. Trusting it once, by package name, stops every check from counting it. Checks
apply trust themselves (`ScanContext.trustedApps`), so summaries and escalations stay right; the
app stays in the evidence, marked "trusted by you, not counted". Limit: trust follows the package
name, not the signing key.

**Reports.** Markdown for people, JSON (`droynis-report`, schema version 1) for tools and `diff`: stable
order and keys, `null` for values that couldn't be read, new fields only added. By default reports
hide `personal` evidence and every IP and MAC address; app names, the model and the Android version
stay, since the findings are about them.

## Suspicious apps

The `SUSP-5xxx` checks look for signs that an installed app is adware or stalkerware. Only user apps
are looked at, since system apps without an icon are normal. Every finding names the signs it saw.

- **Hiding signs:** an app drawer icon turned off after install or off in the manifest, a blank name
  (only invisible characters), or a transparent icon (under 2% visible pixels at 48 px).
- **Concern:** hiding and coming from outside an app store each raise it one step. A store add-on
  without an icon is only listed; a sideloaded app that hides is critical.
- **Behaviour (ADB tier):** what out-of-sight apps did in the last 7 days, from `dumpsys activity
  services` and the app-ops history.
- **Known stalkerware (SUSP-5007):** exact matches of package names and signing-certificate SHA-1s
  against Echap's Stalkerware Indicators (CC BY 4.0), bundled and regenerated with
  `scripts/update-stalkerware-indicators.py`. A key match beats a package name anyone can copy. It
  finds known apps only.
- **Disabled apps:** an app that is installed but disabled can't run or show an icon, so the hiding
  and behaviour checks leave it out and say how many they left out. The checks that match what an
  app is (SUSP-5006, SUSP-5007) read it too.
- **Borrowed names (SUSP-5008):** a user app showing the same name as a system app, compared without
  case, extra space or invisible characters. Counted only from outside an app store; a warning when
  the name is a core app's, such as Settings, which is what a hidden Magisk app is called.
- **Not covered:** hidden root (DenyList, Shamiko), ad SDKs inside normal apps, apps posing as
  system apps by name and icon, and any code scanning.

## Chip flaws

INTG-1013 compares the phone's chip with `ChipFlawData`, a hand-kept list of published boot ROM
flaws: code burned into the chip, so no update fixes it on chips already made. No source publishes
these in a form a script could read, so each entry links its own: the vendor's advisory or CVE
record, or the researchers' write-up (MediaTek's kamakiri chips come from MTK-bypass'
exploits_collection). A chip is listed only when that source names it, and one die sold under
several model numbers is one entry.

- **Severity:** a notice, since every attack needs the phone in hand and restarts it; a warning when
  the screen lock is weaker than Android's "high" rating, because what is left to break is the lock.
- **Scope:** phones and tablets. TVs, modems and IoT parts are left out, and so is any flaw only
  claimed for a chip its vendor and researchers don't name.
- **Limits:** a match means the chip is listed, not that this unit can be broken: makers can turn off
  a boot ROM's download mode, and some chips were fixed in later revisions. A pass means the chip
  isn't on the list.

## Testing

- Checks and parsers: JVM tests with fake probes, including boundaries, and parser mutations (a line
  in another shape, an orphan line) that must fail the parse.
- Scanner: virtual-time tests for timeouts and cancellation, plus a real thread that blocks like a
  hung binder call.
- `CatalogDocTest` fails `check` while CHECKS.md is out of date, and requires every check to say when
  it fails.
- Instrumented tests run the real probes and every check on an emulator, and a Compose test walks
  every screen. Shizuku and root need a real device; tests only check that both stay off without it.
- CI runs unit tests, lint and both builds on pushes to main and on pull requests, and fails
  unless the release APK requests exactly the permissions in `ci/release-permissions.txt` (so never
  `INTERNET`) and the current version has a changelog. Tags run the signed, attested release, which
  refuses an unexpected signing certificate. The reproducible-build check runs on tags, weekly and
  on pull requests that touch the build; the emulator tests run weekly and by hand.
- Supply chain: every GitHub Action is pinned to a commit. zizmor audits the workflows, CodeQL the
  code and OpenSSF Scorecard the repository; dependency review checks pull requests, and
  Dependabot proposes only releases at least a week old. Gradle dependency verification
  is off until `gradle/verification-metadata.xml` is committed
  ([RELEASING.md](RELEASING.md#dependency-verification)).
