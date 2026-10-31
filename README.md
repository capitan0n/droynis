
# Droynis
<img src="fastlane/metadata/android/en-US/images/icon.png" width="96" align="right" alt="">

A read-only security and privacy audit for Android, inspired by Lynis (Android+Lynis). Droynis checks the phone it
runs on, explains every finding, shows the evidence and opens the Settings screen that fixes it. It
never changes anything itself.

> **Not an antivirus or malware scanner.** Droynis doesn't scan apps or files for malicious code and
> doesn't remove anything. It audits how the phone is set up: what is locked, patched, exposed and
> granted. It can point out risky access, such as an app with accessibility or device-admin rights,
> but it can't tell you whether that app is malware.

- 75 checks: device integrity, access control, apps and permissions, network and radios. Every
  check, with when it fails and what to do: **[docs/CHECKS.md](docs/CHECKS.md)**.
- No `INTERNET` permission, no Google Play Services, no analytics. Nothing leaves the phone unless
  you share a report.
- A check passes only on a value it actually read. When Android won't say, the result is Unknown,
  never Passed.

> Droynis is an independent project, not affiliated with, endorsed by or connected to
> [Lynis](https://cisofy.com/lynis/) or CISOfy, and shares no code with it.

## Install

Android 8.0 or later. Pick one:

### 1. F-Droid

[<img src="https://fdroid.gitlab.io/artwork/badge/get-it-on.png" alt="Get it on F-Droid" height="80">](https://f-droid.org/en/packages/io.github.capitan0n.droynis/)

Install from the [F-Droid page](https://f-droid.org/en/packages/io.github.capitan0n.droynis/) or
search for Droynis in the F-Droid client, which also keeps it updated. F-Droid builds each version
from the tagged source, so it may appear a few days after the GitHub release.

### 2. GitHub Releases

Download the APK from [Releases](https://github.com/capitan0n/droynis/releases) and verify it
before installing:

```sh
sha256sum -c droynis-<version>.apk.sha256
gh attestation verify droynis-<version>.apk --repo capitan0n/droynis   # built by GitHub from the tag
```

Each release lists the signing certificate's SHA-256.

### 3. Obtainium

[<img src="art/badge_obtainium.png" alt="Get it on Obtainium" height="80">](https://apps.obtainium.imranr.dev/redirect?r=obtainium://app/%7B%22id%22%3A%22io.github.capitan0n.droynis%22%2C%22url%22%3A%22https%3A%2F%2Fgithub.com%2Fcapitan0n%2Fdroynis%22%2C%22author%22%3A%22capitan0n%22%2C%22name%22%3A%22Droynis%22%7D)

[Obtainium](https://github.com/ImranR98/Obtainium) installs each GitHub release directly, with no
store delay: tap the badge on your phone, or in Obtainium tap **Add App** and enter
`https://github.com/capitan0n/droynis`. Pre-releases are skipped unless you turn on
**Include prereleases**.

On first install, check that the signing certificate matches the SHA-256 in the release notes
(for example with AppVerifier); Android then refuses any update signed with another key.

## Tiers

| Tier | Setup | Adds |
|---|---|---|
| Base | none | 51 checks through public Android APIs |
| ADB | two grants from a computer, once | 11 checks from `dumpsys`: special app access, screen capture without asking, Smart Lock, background camera, microphone and location use, Wi-Fi MAC randomization, open Wi-Fi networks that join automatically |
| Shizuku | the [Shizuku](https://github.com/RikkaApps/Shizuku) app | SELinux, spoofed boot properties, always-on VPN lockdown, SIM PIN, mobile network encryption and fake cell tower alerts; reads what Android hides from apps, and runs the ADB checks |
| Root | opt-in switch in the app | trusted computers, apps with root, root modules, root boot scripts others can change, programs staged in shared temp, root access over ADB, apps listening on the network; runs the ADB and Shizuku checks |

In the app, **⋮ › Check catalog** shows which tiers are active and how to set up the rest. Shizuku
and root run only a fixed set of read-only commands; root stays off until you turn it on.

### Setting up the ADB tier

Android hides `dumpsys` output from apps unless they hold `DUMP` and `PACKAGE_USAGE_STATS`, and only
a computer with `adb` can grant those two. You don't need this if you use Shizuku or root.

1. On the phone, turn on Developer options › USB debugging and connect it to a computer with
   `adb` (Arch/Manjaro: `android-tools`, Debian/Ubuntu: `adb`).
2. Grant the two permissions:

   ```sh
   adb shell pm grant io.github.capitan0n.droynis android.permission.DUMP
   adb shell pm grant io.github.capitan0n.droynis android.permission.PACKAGE_USAGE_STATS
   ```

3. Tap Scan again, then turn USB debugging off; Droynis reports it as a risk when it's on.

The grants survive reboots and stay until you uninstall the app or run the same commands with
`pm revoke`. They let Droynis read, never change, system state.

## Score and reports

The score is passed weight ÷ scored weight × 100 (critical 10, warning 5, notice 2, info 0); a
critical failure caps it at 40. Unknown, N/A and muted checks don't count. Mute what you can't fix,
such as a patch level only the maker can update; the Muted filter has Unmute all.

⋮ › Save the report as Markdown or JSON, share or copy it. **Hide personal details** (on by default)
replaces IP addresses, DNS and proxy servers, the Private DNS host, trusted computers and saved
Wi-Fi network names with `[hidden]`. JSON reports keep a fixed order, so you can compare two scans with `diff`.

## Build

JDK 21 and the Android SDK (compileSdk 37).

```sh
./gradlew check          # unit tests, lint, and docs/CHECKS.md matching the code
./gradlew assembleDebug  # app/build/outputs/apk/debug/app-debug.apk
```

`assembleRelease` signs with `keystore.properties` (git-ignored) or `DROYNIS_*` environment
variables, and builds an unsigned APK without them, as F-Droid expects. Debug builds are slow by
design; use a release build day to day. To publish a release, push a version tag; the one-time
setup is at the top of [.github/workflows/release.yml](.github/workflows/release.yml).

## More

- [docs/DESIGN.md](docs/DESIGN.md): architecture, what Android allows, and why each check works the way it does
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)

Author: Alexandros (capitan0n) · <https://github.com/capitan0n> · [capitan0n@protonmail.com](mailto:capitan0n@protonmail.com)

License: GNU General Public License v3.0 or later (GPL-3.0-or-later), see [LICENSE](LICENSE).
