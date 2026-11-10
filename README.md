# Droynis
<img src="fastlane/metadata/android/en-US/images/icon.png" width="96" align="right" alt="">

A read-only security and privacy audit for Android, inspired by Lynis (Android + Lynis). Droynis
checks the phone it runs on, explains every finding, shows the evidence and opens the Settings
screen that fixes it. It never changes anything itself.

- **90+ checks** in five areas: device integrity, access control, apps and permissions, suspicious
  apps, network and radios. Full list: [docs/CHECKS.md](docs/CHECKS.md).
- **Private:** no `INTERNET` permission, no Google Play Services, no analytics. Nothing leaves the
  phone unless you share a report.
- **Honest:** a check passes only on a value it actually read. When Android won't say, the result
  is Unknown, never Passed.

> **Not an antivirus.** Droynis doesn't scan apps for malicious code or remove anything. It audits
> how the phone is set up, and points out risky access and signs adware leaves, such as an app that
> hides its icon. The one exception is a fixed list: it flags apps that match known stalkerware or
> monitoring apps (SUSP-5007).

## Install

Android 8.0 or later.

| Source | |
|---|---|
| [<img src="https://fdroid.gitlab.io/artwork/badge/get-it-on.png" alt="Get it on F-Droid" height="60">](https://f-droid.org/en/packages/io.github.capitan0n.droynis/) | Built by F-Droid from the tagged source; can arrive a few days after a release. |
| [<img src="art/badge_obtainium.png" alt="Get it on Obtainium" height="60">](https://apps.obtainium.imranr.dev/redirect?r=obtainium://app/%7B%22id%22%3A%22io.github.capitan0n.droynis%22%2C%22url%22%3A%22https%3A%2F%2Fgithub.com%2Fcapitan0n%2Fdroynis%22%2C%22author%22%3A%22capitan0n%22%2C%22name%22%3A%22Droynis%22%7D) | Installs each GitHub release directly. Pre-releases only with **Include prereleases**. |
| [GitHub Releases](https://github.com/capitan0n/droynis/releases) | The APK, with a checksum and a GitHub build attestation. |

To verify a GitHub download:

```sh
sha256sum -c droynis-<version>.apk.sha256
gh attestation verify droynis-<version>.apk --repo capitan0n/droynis
```

Each release lists the signing certificate's SHA-256. Check it on first install (for example with
AppVerifier); Android then refuses any update signed with another key.

## Tiers

Most checks need nothing. More access unlocks more checks; each tier also runs the ones before it.

| Tier | Setup | Adds |
|---|---|---|
| Base | none | everything public Android APIs can read |
| ADB | two grants from a computer, once | `dumpsys` checks: special app access, Smart Lock, background camera, microphone and location use, Wi-Fi privacy, hotspot security |
| Shizuku | the [Shizuku](https://github.com/RikkaApps/Shizuku) app | settings Android hides from apps: SELinux, SIM PIN, always-on VPN lockdown, passkey providers, mobile network encryption |
| Root | opt-in switch in the app | trusted computers, apps with root, root modules, apps listening on the network |

**⋮ › Check catalog** shows which tiers are active and how to set up the rest. Shizuku and root run
only a fixed set of read-only commands, and root stays off until you turn it on.

**ADB tier setup** (not needed with Shizuku or root): turn on USB debugging, connect the phone to a
computer with `adb` (Arch/Manjaro: `android-tools`, Debian/Ubuntu: `adb`) and run:

```sh
adb shell pm grant io.github.capitan0n.droynis android.permission.DUMP
adb shell pm grant io.github.capitan0n.droynis android.permission.PACKAGE_USAGE_STATS
```

Tap Scan again, then turn USB debugging off. The grants survive reboots; `pm revoke` removes them.

## Using it

- **Score:** passed weight ÷ scored weight × 100 (critical 10, warning 5, notice 2, info 0). Any
  critical failure caps it at 40. Unknown, N/A and muted checks don't count.
- **Mute** a check you can't fix, such as a patch only the maker can ship.
- **Trust** an app that needs a lot of access on purpose, such as a watch app: it stays listed but
  stops counting in every check. **⋮ › Trusted apps** lists them.
- **Reports:** save or share as Markdown or JSON from the ⋮ menu. **Hide personal details** (on by
  default) hides IP addresses, DNS and proxy servers, trusted computers and Wi-Fi names. JSON keeps
  a fixed order, so `diff` compares two scans.
- **Scheduled scans** (Reports tab, off by default) run about daily or weekly and can notify you of
  what got worse or got fixed. They add two permissions, notifications and starting after a reboot,
  and keep only each check's last status. If Android holds scans back to save battery, the card
  says so.

## Build

JDK 21 and the Android SDK (compileSdk 37).

```sh
./gradlew check          # unit tests, lint, and docs/CHECKS.md matching the code
./gradlew assembleDebug  # app/build/outputs/apk/debug/app-debug.apk
```

`assembleRelease` signs with `keystore.properties` (git-ignored) or `DROYNIS_*` environment
variables, and builds an unsigned APK without them, as F-Droid expects.

## More

- [docs/CHECKS.md](docs/CHECKS.md): every check and when it fails
- [docs/DESIGN.md](docs/DESIGN.md): how it works, and what Android allows
- [CONTRIBUTING.md](CONTRIBUTING.md): report a wrong result, translate, add a check
- [SECURITY.md](SECURITY.md): report a vulnerability privately

## Credits and license

Droynis is GPL-3.0-or-later ([LICENSE](LICENSE)), by Alexandros (capitan0n) ·
<https://github.com/capitan0n> · [capitan0n@protonmail.com](mailto:capitan0n@protonmail.com).

It is an independent project, not affiliated with, endorsed by or connected to
[Lynis](https://cisofy.com/lynis/) or CISOfy, and shares no code with it.

The stalkerware check uses [Stalkerware Indicators](https://github.com/AssoEchap/stalkerware-indicators)
by [Echap](https://echap.eu.org/), under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Only app names, package names and signing-certificate fingerprints are kept
([scripts/update-stalkerware-indicators.py](scripts/update-stalkerware-indicators.py)). Echap gives
no guarantee that the list is accurate, and asks those who find it useful to consider donating to an
organization that supports women facing violence in their country.
