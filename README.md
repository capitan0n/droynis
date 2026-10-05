# Droynis

A security and privacy audit for Android, inspired by Lynis. Droynis inspects the device it runs
on, explains every finding and suggests a fix. It never changes anything itself.

- GPL-3.0, no Google Play Services, no analytics, no network permission.
- Works without root or Shizuku. An optional ADB tier unlocks extra checks; Shizuku and root
  tiers are planned.
- Every result shows the raw evidence and the API it came from.

Status: early development; base tier and the first ADB-tier check. See
[docs/DESIGN.md](docs/DESIGN.md) for the architecture, the check contract and what the platform
does and does not allow.

> Droynis is an independent project. It is not affiliated with, endorsed by or connected to
> [Lynis](https://cisofy.com/lynis/) or CISOfy, and shares no code with it. Lynis, an audit tool
> for Linux and Unix systems, only inspired the idea of a readable audit with a hardening score.

## The app

- **Dashboard**: security score (0–100) on a ring gauge with a grade (A–F), result counts,
  one card per category and the top issues.
- **Checks**: every check with its result, filterable by result and category:
  green ✓ passed, yellow – needs attention, red ✗ critical, grey ? unknown or N/A.
  Tap a check for why it matters, what to do (with a button to the right Settings screen),
  the raw evidence, a mute switch and technical details.
- **Check catalog** (⋮ menu, or Help): every check, one tab per privilege tier (Base, ADB,
  Shizuku, Root). Each tab says what the tier is and how to set it up: the ADB tab shows which
  permissions are granted right now and the exact adb commands; Shizuku and Root show how they
  will work once they ship.
- **Tools**: network inspector (connection, VPN, Private DNS, DNS servers, Wi-Fi security,
  proxy, IP addresses), which apps hold sensitive permissions, shortcuts to security-related
  Settings screens, device info and the report export (save as Markdown or JSON, share, copy).
- **Help**: what the symbols and the score mean, privacy and FAQ.
- Menu: scan again, save the report as Markdown or JSON, share/copy it, check catalog,
  light/dark/system theme, and an About page (author, source code, feedback).

### Muting a check

Some findings are out of your hands; security patch age, for one, depends on the manufacturer.
Open the check (or find it in the check catalog) and turn on **Mute this check**. A muted check
still runs and shows its real result, but the score, the critical cap, the counts and the issue
lists leave it out. The dashboard shows how many checks are muted, and both reports list them, so
a muted score never passes for an unmuted one.

## Checks (base tier)

| ID | Check | Severity | Fails when |
|---|---|---|---|
| INTG-1010 | Security patch age | Warning (critical > 1 year) | patch level older than 90 days |
| INTG-1020 | Storage encryption | Critical | storage unencrypted, or encrypted only with the default key |
| INTG-1040 | Bootloader lock | Critical | bootloader unlocked or verified boot not passing (hardware key attestation, boot properties as fallback) |
| INTG-1041 | OEM unlocking | Notice | the OEM unlocking switch is on |
| INTG-1050 | Root access | Critical | an su binary, root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found |
| INTG-1060 | Android build | Warning | userdebug/eng build, public test keys or `ro.debuggable=1` |
| INTG-1070 | WebView updates | Warning | WebView not updated for more than 60 days |
| INTG-1030 | Advanced Protection (Android 16+) | Info | Advanced Protection is off |
| ACCS-2001 | Secure lock screen | Critical | no PIN, pattern or password |
| ACCS-2002 | Screen timeout | Notice | screen stays on longer than 2 minutes |
| ACCS-2005 | Stay awake while charging | Notice | the screen never turns off (or locks) while charging |
| ACCS-2003 | Password visibility | Notice | typed password characters are shown |
| ACCS-2004 | Lock screen notifications | Notice | notification content visible while locked |
| ACCS-2010 | Developer options | Notice | developer options enabled |
| ACCS-2011 | USB debugging | Warning | adb over USB enabled |
| ACCS-2012 | Wireless debugging (Android 11+) | Warning | adb over Wi-Fi enabled |
| APPS-4001 | Accessibility services | Notice | any accessibility service enabled |
| APPS-4002 | Device admin apps | Notice | any device admin active |
| APPS-4005 | Notification access | Notice | an app can read all notifications |
| APPS-4006 | Keyboard apps | Notice | a third-party keyboard is enabled |
| APPS-4003 | Debuggable apps | Warning | an installed app is debuggable |
| APPS-4004 | Apps from unknown sources | Notice | an app came from outside a known app store |
| APPS-4007 | Apps built for old Android | Notice | a user app targets Android 8.1 (API 27) or older |
| NETW-3001 | Private DNS (Android 9+) | Warning | DNS not encrypted and no VPN |
| NETW-3002 | VPN | Info | no VPN active |
| NETW-3005 | Wi-Fi security (Android 12+) | Warning | connected to an open or WEP network without VPN |
| NETW-3007 | HTTP proxy | Warning | web traffic goes through a proxy |
| NETW-3003 | User CA certificates | Warning | a user-installed CA can intercept TLS |
| NETW-3004 | Bluetooth | Notice | Bluetooth is on |
| NETW-3006 | NFC | Info | NFC is on |

## Checks (ADB tier)

Optional. They show as N/A, and do not change the score, until you grant two read-only
permissions once from a computer:

```sh
adb shell pm grant io.github.capitan0n.droynis android.permission.DUMP
adb shell pm grant io.github.capitan0n.droynis android.permission.PACKAGE_USAGE_STATS
```

Then tap Scan again; ⋮ › Check catalog › ADB shows the same commands and whether each permission
is granted. USB debugging can be turned off afterwards; the grants stay until
`adb shell pm revoke …` or an uninstall. The Settings › Usage access switch alone is not enough:
`dumpsys appops` asks for the `PACKAGE_USAGE_STATS` permission itself. DUMP lets an app read
system diagnostics, so Droynis reads only what its checks need, keeps nothing and has no network
access.

| ID | Check | Severity | Fails when |
|---|---|---|---|
| APPS-4101 | Background camera, microphone and location use (Android 10+) | Notice (warning for camera or microphone) | a user app used the camera, microphone or location while in the background in the last 7 days (`dumpsys appops`) |

## Results and score

A check passes only after reading a passing value. When Android will not say, the result is
Unknown, never Passed: on Android 17, for example, apps may be shown USB debugging and developer
options as off whatever their real state, so a "0" there counts as Unknown.

Score: passed weight / scored weight × 100, with weights critical 10, warning 5, notice 2, info 0.
A critical failure caps the score at 40, because one critical gap (no screen lock, unlocked
bootloader, root) undoes most other protections; the app and reports also show the score without
the cap. Unknown and N/A results do not count, and neither do muted checks.

## Comparing scans

Save the report as JSON (⋮ › Save report (JSON)). The layout is versioned (`schemaVersion`) and
findings keep a fixed order, so two scans diff cleanly:

```sh
jq -r '.findings[] | "\(.id)\t\(.verdict)\t\(.summary)"' old.json > old.tsv
jq -r '.findings[] | "\(.id)\t\(.verdict)\t\(.summary)"' new.json > new.tsv
diff old.tsv new.tsv
jq '.score' new.json
```

Muted checks keep their result in `findings` with `"muted": true`, are listed in `score.muted`, and
are left out of `score` and `verdicts`. Compare scores only between reports with the same
`score.muted`.

## Build

Requires JDK 17+ and the Android SDK (compileSdk 37).

```sh
./gradlew check            # unit tests and lint
./gradlew assembleDebug    # app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Debug builds are slow by design (no R8, debuggable runtime), which shows as scroll jank. For
daily use build a release, signed with your own key:

```sh
keytool -genkeypair -v -keystore droynis.jks -alias droynis -keyalg RSA -keysize 4096 -validity 10000
cat > keystore.properties <<'END'
storeFile=droynis.jks
storePassword=YOUR_PASSWORD
keyAlias=droynis
keyPassword=YOUR_PASSWORD
END
./gradlew assembleRelease  # app/build/outputs/apk/release/app-release.apk
```

`keystore.properties` and `*.jks` are git-ignored. Without them, `assembleRelease` produces an
unsigned APK (as F-Droid expects). A release-signed app cannot update a debug-signed one: run
`adb uninstall io.github.capitan0n.droynis` once before switching.

The pure-Kotlin modules (`core-model`, `checks-base`, `checks-adb`, `report`) hold all check
logic and run on any JVM; only `platform-android` and `app` touch Android APIs.

## Author

Alexandros – capitan0n · <https://github.com/capitan0n/droynis> · feedback:
[capitan0n@protonmail.com](mailto:capitan0n@protonmail.com)

## License

GNU General Public License v3. See [LICENSE](LICENSE).
