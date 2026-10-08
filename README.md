
# Droynis
<img src="fastlane/metadata/android/en-US/images/icon.png" width="96" align="right" alt="">

A read-only security and privacy audit for Android, inspired by Lynis (Android+Lynis). Droynis checks the phone it
runs on, explains every finding, shows the evidence and opens the Settings screen that fixes it. It
never changes anything itself.

> **Not an antivirus or malware scanner.** Droynis doesn't scan apps or files for malicious code and
> doesn't remove anything. It audits how the phone is set up: what is locked, patched, exposed and
> granted. It can point out risky access, such as an app with accessibility or device-admin rights,
> but it can't tell you whether that app is malware.

- 54 checks: device integrity, access control, apps and permissions, network and radios. Every
  check, with when it fails and what to do: **[docs/CHECKS.md](docs/CHECKS.md)**.
- No `INTERNET` permission, no Google Play Services, no analytics. Nothing leaves the phone unless
  you share a report.
- A check passes only on a value it actually read. When Android won't say, the result is Unknown,
  never Passed.

> Droynis is an independent project, not affiliated with, endorsed by or connected to
> [Lynis](https://cisofy.com/lynis/) or CISOfy, and shares no code with it.

## Install

Android 8.0 or later. Download the APK from [Releases](https://github.com/capitan0n/droynis/releases)
and verify it before installing:

```sh
sha256sum -c droynis-<version>.apk.sha256
gh attestation verify droynis-<version>.apk --repo capitan0n/droynis   # built by GitHub from the tag
```

Each release lists the signing certificate's SHA-256. F-Droid: on its way.

## Tiers

| Tier | Setup | Adds |
|---|---|---|
| Base | none | 39 checks through public Android APIs |
| ADB | two grants from a computer, once | 8 checks from `dumpsys`: special app access, Smart Lock, background camera, microphone and location use |
| Shizuku | the [Shizuku](https://github.com/RikkaApps/Shizuku) app | SELinux, always-on VPN lockdown, SIM PIN; reads what Android hides from apps, and runs the ADB checks |
| Root | opt-in switch in the app | trusted computers, apps with root, root modules, apps listening on the network; runs the ADB and Shizuku checks |

```sh
adb shell pm grant io.github.capitan0n.droynis android.permission.DUMP
adb shell pm grant io.github.capitan0n.droynis android.permission.PACKAGE_USAGE_STATS
```

⋮ › Check catalog shows each tier's status and setup. Shizuku and root run only a fixed set of
read-only commands and reads; root is off until you turn it on.

## Score and reports

The score is passed weight ÷ scored weight × 100 (critical 10, warning 5, notice 2, info 0); a
critical failure caps it at 40. Unknown, N/A and muted checks don't count. Mute what you can't fix,
such as a patch level only the maker can update; the Muted filter has Unmute all.

⋮ › Save the report as Markdown or JSON, share or copy it. **Hide personal details** (on by default)
replaces IP addresses, DNS and proxy servers, the Private DNS host and trusted computers with
`[hidden]`. JSON keeps a fixed order, so two scans diff cleanly:

```sh
jq -r '.findings[] | "\(.id)\t\(.verdict)\t\(.summary)"' scan.json
```

## Build

JDK 17+ and the Android SDK (compileSdk 37).

```sh
./gradlew check          # unit tests, lint, and docs/CHECKS.md matching the code
./gradlew assembleDebug  # app/build/outputs/apk/debug/app-debug.apk
```

`assembleRelease` signs with `keystore.properties` (git-ignored) or `DROYNIS_*` environment
variables, and builds an unsigned APK without them, as F-Droid expects. Debug builds are slow by
design; use a release build day to day. Releases: [docs/RELEASING.md](docs/RELEASING.md).

## More

- [docs/DESIGN.md](docs/DESIGN.md): architecture, what Android allows, and why each check works the way it does
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)

Author: Alexandros (capitan0n) · <https://github.com/capitan0n> · [capitan0n@protonmail.com](mailto:capitan0n@protonmail.com)

License: GNU General Public License v3.0 or later (GPL-3.0-or-later), see [LICENSE](LICENSE).
