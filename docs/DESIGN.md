# How Droynis works

Droynis reads Android settings and shows the evidence behind each finding. When a fix is
available, it opens the relevant Settings screen so you can make the change yourself.

## What access allows

| Access | What Droynis can read |
| --- | --- |
| Base | Public Android APIs in the profile where Droynis runs. It requests `QUERY_ALL_PACKAGES` because Android’s default package filtering would hide apps from checks that list them. |
| ADB | Two permissions granted through ADB let Droynis read diagnostic output from services such as Wi-Fi and app-ops. If a parser can’t interpret the relevant output, the result is Unknown. |
| Shizuku | Shizuku starts a service from the Droynis APK as Android’s shell user. The service exposes specific reads, such as a settings lookup, and has no general command interface. |
| Root | Root is off by default. When enabled, Droynis opens one root session per scan and runs predefined commands. It closes the session when the scan ends or a command times out. Where both Shizuku and root can supply a reading, Droynis prefers Shizuku. |

## What a result means

A check can pass only when Droynis reads evidence for it. **Unknown** means the check could
apply, but the available evidence can’t settle it. For example, on Android 17 a normal app can
read the USB debugging setting as off even when it is on. That reading alone can’t earn a pass.

**N/A** means the check didn’t apply or couldn’t run at the available access level. Unknown
and N/A both stay out of the score. Muting a check also excludes it from the score, while
keeping its result visible in reports. See the [check catalog](CHECKS.md) for individual
checks and their failure conditions.

## Privacy and reports

The APK has no `INTERNET` permission. Scans run on the phone. When you share a report,
**Hide personal details** is on by default and hides values such as IP addresses, Wi-Fi
names and trusted computers. App names, the phone model and the Android version remain
visible so the recipient can interpret the findings.

## Code layout

- [platform/android](../platform/android) reads Android APIs and implements the Shizuku and root services.
- [checks](../checks) contains the check logic for each tier. Separating that logic from Android
  lets JVM tests supply readings from different devices, including missing or unreadable values.
- [core/model](../core/model) runs the checks and records results and evidence.
  [core/report](../core/report) calculates the score and exports Markdown and JSON.
- [app](../app) contains the UI, Settings links and scheduled scans.

See [CONTRIBUTING.md](../CONTRIBUTING.md) to add a check or report a wrong result.
