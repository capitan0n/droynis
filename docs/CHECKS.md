# Droynis checks

<!-- Generated from the check definitions by CatalogDocTest. Don't edit by hand: after
     changing a check, run UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test -->

121 checks. Each one's full explanation and fix are in the app: tap the check.

- A check passes only on a value it read; otherwise it is Unknown or N/A, never Passed.
- A failure weighs by severity (critical 10, warning 5, notice 2, info 0); any critical failure caps the score at 40.
- Higher tiers need setup ([README](../README.md#tiers)) and also run every check of the tiers before them.

| Category | Base | ADB | Shizuku | Root | All |
|---|---|---|---|---|---|
| [Device integrity](#device-integrity) | 16 | – | 2 | 3 | 21 |
| [Access control](#access-control) | 17 | 1 | 2 | 2 | 22 |
| [Apps and permissions](#apps-and-permissions) | 22 | 11 | 2 | 4 | 39 |
| [Suspicious apps](#suspicious-apps) | 9 | 5 | – | – | 14 |
| [Network and radios](#network-and-radios) | 13 | 7 | 3 | 2 | 25 |
| **All** | 77 | 24 | 9 | 11 | 121 |

## Device integrity

| ID | Check | Tier | Severity | Fails when |
|---|---|---|---|---|
| INTG-1010 | Security patch age | Base | Warning | the security patch is older than 90 days (critical when over a year old) |
| INTG-1011 | Vendor and kernel patch level | Base | Warning | the vendor or kernel patch is more than 90 days older than Android's (critical beyond a year) |
| INTG-1012 | Google Play system update (Android 10+) | Base | Notice | the Google Play system update is older than 180 days (a warning when over a year old) |
| INTG-1013 | Chip with an unfixable boot flaw | Base | Notice | the chip has a published boot ROM flaw no update can fix, such as Qualcomm's CVE-2026-25262 or MediaTek's kamakiri (a warning when the screen lock isn't a strong PIN or password) |
| INTG-1020 | Storage encryption | Base | Critical | storage is unencrypted, or encrypted only with the default key |
| INTG-1021 | StrongBox security chip (Android 9+) | Base | Notice | the phone has no StrongBox security chip for keys |
| INTG-1030 | Advanced Protection (Android 16+) | Base | Info | Advanced Protection is off |
| INTG-1031 | Managed by an organization | Base | Info | a device or profile owner manages this user, or an organization owns the phone (information only; a warning when the owner came from outside an app store) |
| INTG-1040 | Bootloader lock | Base | Critical | the bootloader is unlocked or verified boot isn't passing (hardware key attestation, boot properties as a fallback) |
| INTG-1041 | OEM unlocking | Base | Notice | the OEM unlocking switch is on (not applicable once the bootloader is unlocked) |
| INTG-1050 | Root access | Base | Critical | an su binary, a root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found, or Droynis itself was given a root shell |
| INTG-1060 | Android build | Base | Warning | it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1 (critical when ro.adb.secure=0 lets adb in without authorization) |
| INTG-1070 | WebView updates | Base | Warning | WebView hasn't been updated for more than 60 days, or its Chromium version is older than that |
| INTG-1080 | Time since restart | Base | Notice | the phone hasn't restarted for more than 7 days |
| INTG-1090 | Storage space | Base | Notice | more than 80% of the internal storage is in use |
| INTG-1091 | Unencrypted SD card or USB drive | Base | Notice | an SD card or USB drive is mounted as portable storage, which Android doesn't encrypt |
| INTG-1201 | SELinux mode | Shizuku | Critical | SELinux is permissive or disabled |
| INTG-1202 | Spoofed boot properties | Shizuku | Warning | a security-relevant ro.boot.* property differs from the kernel command line (a props spoofer) |
| INTG-1301 | Root modules | Root | Info | an enabled root module is installed (information only) |
| INTG-1302 | Root boot code others can change | Root | Notice | a boot script root runs, or a folder holding it, is not owned by root or is writable by others |
| INTG-1303 | Programs staged in shared temp | Root | Notice | a script or executable is staged in /data/local/tmp |

## Access control

| ID | Check | Tier | Severity | Fails when |
|---|---|---|---|---|
| ACCS-2001 | Secure lock screen | Base | Critical | no PIN, pattern or password is set |
| ACCS-2002 | Screen timeout | Base | Notice | the screen stays on for more than 2 minutes |
| ACCS-2003 | Password visibility | Base | Notice | typed password characters are shown |
| ACCS-2004 | Lock screen notifications | Base | Notice | notification content is visible while the phone is locked |
| ACCS-2005 | Stay awake while charging | Base | Notice | the screen never turns off, so never locks, while charging |
| ACCS-2006 | Lock after screen timeout | Base | Notice | the phone stays unlocked for more than 30 seconds after the screen turns off |
| ACCS-2007 | Screen lock strength (Android 10+) | Base | Notice | the screen lock is a pattern or a PIN with repeated or ordered digits |
| ACCS-2008 | Notification history (Android 11+) | Base | Notice | notification history is on, keeping 24 hours of notification text |
| ACCS-2009 | Biometric unlock strength (Android 11+) | Base | Notice | the only biometric unlock set up is weak (Class 2), such as most camera-only face unlock |
| ACCS-2010 | Developer options | Base | Notice | developer options are on |
| ACCS-2011 | USB debugging | Base | Warning | adb over USB is on |
| ACCS-2012 | Wireless debugging (Android 11+) | Base | Warning | adb over Wi-Fi is on |
| ACCS-2013 | USB debugging authorization timeout (Android 11+) | Base | Notice | computers allowed for USB debugging keep their access for more than 7 days without connecting, or for good |
| ACCS-2014 | Unlock required after app pinning | Base | Notice | app pinning is on and unpinning does not require unlocking |
| ACCS-2015 | Add users from the lock screen | Base | Notice | the lock-screen switch for adding users is on and the profile can add users |
| ACCS-2020 | Remote lock and erase | Base | Notice | no app or known service can lock and erase the phone remotely |
| ACCS-2021 | Google theft protection (Android 10+) | Base | Info | never (manual review of Google theft protection) |
| ACCS-2101 | Smart Lock and Extend Unlock | ADB | Notice | a trust agent such as Smart Lock can keep the phone unlocked |
| ACCS-2201 | SIM card PIN (Android 11+) | Shizuku | Notice | a SIM in use has its PIN turned off |
| ACCS-2202 | Device controls on the lock screen (Android 13+) | Shizuku | Notice | device controls can be used without unlocking the phone |
| ACCS-2301 | Computers trusted for USB debugging | Root | Notice | a computer is trusted for USB debugging |
| ACCS-2302 | Magisk superuser prompt protections | Root | Notice | user authentication or tapjacking protection is confirmed off for Magisk prompts |

## Apps and permissions

| ID | Check | Tier | Severity | Fails when |
|---|---|---|---|---|
| APPS-4001 | Accessibility services | Base | Notice | any accessibility service is enabled (a warning when its app came from outside an app store) |
| APPS-4002 | Device admin apps | Base | Notice | a device admin you installed, or a device or profile owner, is active (a warning when it came from outside an app store) |
| APPS-4003 | Debuggable apps | Base | Warning | an installed app is debuggable |
| APPS-4004 | Apps from unknown sources | Base | Notice | an app came from outside a known app store |
| APPS-4005 | Notification access | Base | Notice | an app you installed can read all notifications (a warning when it came from outside an app store) |
| APPS-4006 | Keyboard apps | Base | Notice | a third-party keyboard is enabled |
| APPS-4007 | Apps built for old Android | Base | Notice | a user app targets Android 8.1 (API 27) or older |
| APPS-4008 | Apps that can read your SMS or call log | Base | Notice | an app other than your SMS and phone apps, or one of those installed from outside an app store, can read SMS or the call log (a warning when it came from outside an app store) |
| APPS-4009 | Apps that can send SMS | Base | Notice | an app other than your SMS app can send SMS (a warning when it came from outside an app store) |
| APPS-4010 | Autofill service (Android 9+) | Base | Notice | an autofill service from an app you installed is selected (a warning when it came from outside an app store) |
| APPS-4011 | Digital assistant app | Base | Notice | the digital assistant is an app you installed (a warning when it came from outside an app store) |
| APPS-4012 | Apps with location all the time (Android 10+) | Base | Notice | an app you installed may use location all the time (a warning when it came from outside an app store) |
| APPS-4013 | Apps that skip battery optimization | Base | Info | an app you installed may skip battery optimization (information only) |
| APPS-4014 | Google Play services | Base | Info | Google Play services is built into the system, with privileged access (information only) |
| APPS-4015 | App scanning (Play Protect) | Base | Warning | the install-time app verifier, Play Protect scanning, or the separate ADB verification switch is off |
| APPS-4016 | Apps with Shizuku access | Base | Notice | an app other than Droynis may use Shizuku (a warning when it came from outside an app store, or Shizuku runs as root) |
| APPS-4017 | Profiles this scan doesn't cover | Base | Info | another profile shares this user, Droynis doesn't run in the phone's main user, or (ADB tier and up) the phone has another user or profile (information only) |
| APPS-4018 | Apps that allow unencrypted connections | Base | Info | an app you installed has network access and declares that it may connect without encryption (information only) |
| APPS-4019 | Apps that can run commands through Termux or Tasker | Base | Notice | another app may run commands in Termux or start Tasker tasks (a warning when it came from outside an app store) |
| APPS-4020 | Apps with system permissions granted over adb | Base | Warning | an app you installed holds WRITE_SECURE_SETTINGS, READ_LOGS, DUMP or INTERACT_ACROSS_USERS, which only adb, Shizuku or root can grant |
| APPS-4021 | Active spell checker | Base | Info | never (reports the enabled spell checker) |
| APPS-4022 | Android backup status | Base | Info | never (reports the Android backup switch) |
| APPS-4102 | Apps that can draw over other apps (Android 10+) | ADB | Notice | a user app may display over other apps |
| APPS-4103 | Apps with access to all files (Android 11+) | ADB | Notice | a user app has all files access |
| APPS-4104 | Apps that can install other apps (Android 10+) | ADB | Notice | a user app other than a known app store may install apps |
| APPS-4105 | Apps with usage access (Android 10+) | ADB | Notice | a user app has usage access |
| APPS-4106 | Apps that can change system settings (Android 10+) | ADB | Info | a user app may change system settings (information only) |
| APPS-4107 | Apps that can manage your media (Android 12+) | ADB | Info | a user app may change or delete media without asking (information only) |
| APPS-4109 | Apps that keep their permissions while unused (Android 11+) | ADB | Info | a user app is exempt from having its permissions removed while unused (information only) |
| APPS-4110 | Printing services (Android 9+) | ADB | Info | never (inventory of installed printing services and their switches) |
| APPS-4111 | Apps allowed to fake location (Android 10+) | ADB | Notice | a user app has mock location access |
| APPS-4112 | Apps allowed to show full-screen alerts (Android 14+) | ADB | Info | never (reports apps with full-screen alert access) |
| APPS-4113 | Camera and microphone privacy switches (Android 12+) | ADB | Info | never (reports the camera and microphone privacy switches) |
| APPS-4201 | Passkey and password providers (Android 14+) | Shizuku | Notice | a passkey or password provider from an app you installed is turned on (a warning when it came from outside an app store) |
| APPS-4202 | Clipboard access alerts (Android 12+) | Shizuku | Notice | "Show clipboard access" is off, so apps read the clipboard silently |
| APPS-4301 | Apps with root access | Root | Warning | an app other than Droynis may get root |
| APPS-4302 | Root access over ADB | Root | Warning | Magisk allows ADB to request root, or the ADB shell has an unexpired Magisk 31.1 grant |
| APPS-4303 | Apps allowed to text premium numbers | Root | Warning | an app's Premium SMS access is set to Always allow |
| APPS-4304 | LSPosed modules and their scope | Root | Info | LSPosed's policy test denies the required rule (information only) |

## Suspicious apps

| ID | Check | Tier | Severity | Fails when |
|---|---|---|---|---|
| SUSP-5001 | Apps hiding from the app drawer | Base | Warning | an installed app turned its app drawer icon off, or shows a blank name or a transparent icon (critical when it came from outside an app store, or has accessibility, device admin or notification access) |
| SUSP-5002 | Hidden apps set up to run in the background | Base | Warning | an app that hides from the app drawer, or one without an icon from outside an app store, declares it starts at boot, runs foreground services, draws over other apps, shows full-screen pop-ups or skips battery limits (critical when it hides and came from outside an app store) |
| SUSP-5003 | Hidden apps showing screens | Base | Warning | an app that hides from the app drawer, or one without an icon from outside an app store, brought its own screen to the front in the last 7 days (critical when it hides and came from outside an app store) |
| SUSP-5004 | Apps installed by another app | Base | Warning | an app was installed by another app you installed that isn't an app store or an installer tool |
| SUSP-5005 | Apps with banking-trojan permissions | Base | Warning | an installed app declares an accessibility service and asks for SMS and to draw over other apps (critical when it came from outside an app store or its accessibility service is on) |
| SUSP-5006 | Apps signed with a debug or test key | Base | Notice | a user app is signed with Android's debug key or a public test key (warning for a test key, or a debug key on an app that isn't debuggable) |
| SUSP-5007 | Known stalkerware and monitoring apps (inactive) | Base | Info | never (inactive by design) |
| SUSP-5008 | Apps using a built-in app's name | Base | Notice | an app from outside an app store shows the same name as an app that came with the phone (a warning when that app is a core one, such as Settings or Google Play services) |
| SUSP-5009 | Apps posing as an app store | Base | Warning | a user app uses the package name of an app store whose signing keys Droynis knows, but none of them (critical when it has installed other apps) |
| SUSP-5101 | Hidden apps running in the background (Android 10+) | ADB | Warning | an app that hides from the app drawer, or one without an icon from outside an app store, runs a service it started, or started a foreground service or drew over other apps in the last 7 days (critical when it hides and came from outside an app store) |
| SUSP-5102 | Background camera, microphone and location use (Android 10+) | ADB | Notice | a user app used the camera, microphone or location from the background in the last 7 days (warning for camera or microphone) |
| SUSP-5103 | Apps that can record the screen without asking (Android 10+) | ADB | Warning | a user app may record or cast the screen without asking |
| SUSP-5104 | Background SMS, call log and contacts use (Android 10+) | ADB | Notice | a user app read SMS, the call log or contacts, or received SMS, from the background in the last 7 days (warning when it came from outside an app store) |
| SUSP-5105 | Active screen capture | ADB | Warning | Android's MediaProjection service reports an active screen capture or mirroring session |

## Network and radios

| ID | Check | Tier | Severity | Fails when |
|---|---|---|---|---|
| NETW-3001 | Private DNS (Android 9+) | Base | Warning | Private DNS is inactive and no VPN is active |
| NETW-3002 | VPN | Base | Info | no VPN is active |
| NETW-3003 | User CA certificates | Base | Warning | a user-installed CA certificate can intercept TLS |
| NETW-3004 | Bluetooth | Base | Notice | Bluetooth is on |
| NETW-3005 | Wi-Fi security (Android 12+) | Base | Warning | the phone is on an open or WEP Wi-Fi network |
| NETW-3006 | NFC | Base | Info | NFC is on |
| NETW-3007 | HTTP proxy | Base | Warning | web traffic on Wi-Fi, mobile data or another network goes through an HTTP proxy |
| NETW-3008 | Location | Base | Notice | Location is on |
| NETW-3009 | Wi-Fi and Bluetooth scanning | Base | Notice | Wi-Fi or Bluetooth scanning is on |
| NETW-3010 | 2G mobile networks | Base | Notice | a SIM in use may connect to 2G networks |
| NETW-3011 | Secure NFC (Android 10+) | Base | Notice | NFC is on and works while the phone is locked |
| NETW-3012 | Added system CA certificates | Base | Warning | a CA certificate was added to the system store, which every app trusts (by a root module or a modified system) |
| NETW-3013 | Active tethering | Base | Info | the phone is sharing a connection (information only) |
| NETW-3101 | Wi-Fi MAC randomization (Android 10+) | ADB | Notice | the current Wi-Fi connection or a saved network uses the phone's own MAC address |
| NETW-3102 | Open Wi-Fi networks that join automatically (Android 12+) | ADB | Notice | a saved open, Enhanced Open or WEP network joins automatically |
| NETW-3103 | Hotspot security (Android 14+) | ADB | Notice | the hotspot has no password (a warning), or doesn't turn off by itself when no device is connected |
| NETW-3104 | Hidden Wi-Fi networks (Android 12+) | ADB | Notice | a saved Wi-Fi network is hidden, so the phone calls out its name when it looks for Wi-Fi |
| NETW-3105 | Saved Wi-Fi networks with broken encryption (Android 12+) | ADB | Notice | a saved Wi-Fi network uses WEP |
| NETW-3106 | Call forwarding | ADB | Warning | a SIM in use forwards all calls to another number |
| NETW-3107 | Hotspot 2.0 (Passpoint) | ADB | Info | never (reports the Passpoint switch and readable provider settings) |
| NETW-3201 | Always-on VPN lockdown | Shizuku | Notice | an always-on VPN lets traffic out while it is down |
| NETW-3202 | Mobile network encryption (Android 14+) | Shizuku | Notice | the phone accepts mobile connections without encryption (Require encryption is off) |
| NETW-3203 | Mobile network security alerts (Android 15+) | Shizuku | Notice | the phone doesn't warn about signs of a fake cell tower (Network notifications are off) |
| NETW-3301 | Apps listening on the network | Root | Notice | a user app accepts connections from the network |
| NETW-3302 | Quick Share visibility | Root | Notice | Quick Share (Nearby Share) is visible to everyone nearby |
