# Droynis

A Lynis-style security and privacy audit for Android. Droynis inspects the device it runs on,
explains every finding and suggests a fix. It never changes anything itself.

- GPL-3.0, no Google Play Services, no analytics, no network permission.
- Works without root or Shizuku; optional ADB and Shizuku tiers are planned for extra checks.
- Every result shows the raw evidence and the API it came from.

Status: early development, base tier only. See [docs/DESIGN.md](docs/DESIGN.md) for the
architecture, the check contract and what the platform does and does not allow.

## The app

- **Dashboard**: security score (0–100) on a ring gauge with a grade (A–F), result counts,
  one card per category and the top issues.
- **Checks**: every check with its result, filterable by result and category:
  green ✓ passed, yellow – needs attention, red ✗ critical, grey ? unknown or N/A.
  Tap a check for why it matters, what to do (with a button to the right Settings screen),
  the raw evidence and technical details.
- **Tools**: network inspector (connection, VPN, Private DNS, DNS servers, Wi-Fi security,
  proxy, IP addresses), which apps hold sensitive permissions, shortcuts to security-related
  Settings screens, device info and the report export (save as Markdown, share, copy).
- **Help**: what the symbols and the score mean, the full check catalog, privilege tiers,
  privacy and FAQ.
- Menu: scan again, save/share/copy report, light/dark/system theme, about.

## Checks (base tier)

| ID | Check | Severity | Fails when |
|---|---|---|---|
| INTG-1010 | Security patch age | Warning (critical > 1 year) | patch level older than 90 days |
| INTG-1020 | Storage encryption | Critical | storage unencrypted, or encrypted only with the default key |
| INTG-1030 | Advanced Protection (Android 16+) | Info | Advanced Protection is off |
| ACCS-2001 | Secure lock screen | Critical | no PIN, pattern or password |
| ACCS-2002 | Screen timeout | Notice | screen stays on longer than 2 minutes |
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
| NETW-3001 | Private DNS (Android 9+) | Warning | DNS not encrypted and no VPN |
| NETW-3002 | VPN | Info | no VPN active |
| NETW-3005 | Wi-Fi security (Android 12+) | Warning | connected to an open or WEP network without VPN |
| NETW-3003 | User CA certificates | Warning | a user-installed CA can intercept TLS |
| NETW-3004 | Bluetooth | Notice | Bluetooth is on |
| NETW-3006 | NFC | Info | NFC is on |

A check passes only after reading a passing value. When Android will not say, the result is
Unknown, never Passed: on Android 17, for example, apps may be shown USB debugging and developer
options as off whatever their real state, so a "0" there counts as Unknown.

Score: passed weight / scored weight × 100, with weights critical 10, warning 5, notice 2, info 0.
A critical failure caps the score at 40. Unknown and N/A results do not count.

## Build

Requires JDK 17+ and the Android SDK (compileSdk 37).

```sh
./gradlew check            # unit tests and lint
./gradlew assembleDebug    # app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The pure-Kotlin modules (`core-model`, `checks-base`, `report`) hold all check logic and run on
any JVM; only `platform-android` and `app` touch Android APIs.

## License

GNU General Public License v3. See [LICENSE](LICENSE).
