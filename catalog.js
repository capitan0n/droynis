/* Droynis beta catalog, commit a5f6c837925cb6d8267c1e4838b5e86354ab1bff */
window.DROYNIS_CHECKS = [
  {
    "id": "INTG-1010",
    "title": "Security patch age",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "the security patch is older than 90 days (critical when over a year old)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1011",
    "title": "Vendor and kernel patch level",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "the vendor or kernel patch is more than 90 days older than Android's (critical beyond a year)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1012",
    "title": "Google Play system update (Android 10+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the Google Play system update is older than 180 days (a warning when over a year old)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1013",
    "title": "Chip with an unfixable boot flaw",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the chip has a published boot ROM flaw no update can fix, such as Qualcomm's CVE-2026-25262 or MediaTek's kamakiri (a warning when the screen lock isn't a strong PIN or password)",
    "category": "Device integrity",
    "betaAdded": true
  },
  {
    "id": "INTG-1020",
    "title": "Storage encryption",
    "tier": "Base",
    "severity": "Critical",
    "failsWhen": "storage is unencrypted, or encrypted only with the default key",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1021",
    "title": "StrongBox security chip (Android 9+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the phone has no StrongBox security chip for keys",
    "category": "Device integrity",
    "betaAdded": true
  },
  {
    "id": "INTG-1030",
    "title": "Advanced Protection (Android 16+)",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "Advanced Protection is off",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1031",
    "title": "Managed by an organization",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "a device or profile owner manages this user, or an organization owns the phone (information only; a warning when the owner came from outside an app store)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1040",
    "title": "Bootloader lock",
    "tier": "Base",
    "severity": "Critical",
    "failsWhen": "the bootloader is unlocked or verified boot isn't passing (hardware key attestation, boot properties as a fallback)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1041",
    "title": "OEM unlocking",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the OEM unlocking switch is on (not applicable once the bootloader is unlocked)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1050",
    "title": "Root access",
    "tier": "Base",
    "severity": "Critical",
    "failsWhen": "an su binary, a root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found, or Droynis itself was given a root shell",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1060",
    "title": "Android build",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1 (critical when ro.adb.secure=0 lets adb in without authorization)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1070",
    "title": "WebView updates",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "WebView hasn't been updated for more than 60 days, or its Chromium version is older than that",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1080",
    "title": "Time since restart",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the phone hasn't restarted for more than 7 days",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1090",
    "title": "Storage space",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "more than 80% of the internal storage is in use",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1091",
    "title": "Unencrypted SD card or USB drive",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an SD card or USB drive is mounted as portable storage, which Android doesn't encrypt",
    "category": "Device integrity",
    "betaAdded": true
  },
  {
    "id": "INTG-1201",
    "title": "SELinux mode",
    "tier": "Shizuku",
    "severity": "Critical",
    "failsWhen": "SELinux is permissive or disabled",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1202",
    "title": "Spoofed boot properties",
    "tier": "Shizuku",
    "severity": "Warning",
    "failsWhen": "a security-relevant ro.boot.* property differs from the kernel command line (a props spoofer)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1301",
    "title": "Root modules",
    "tier": "Root",
    "severity": "Info",
    "failsWhen": "an enabled root module is installed (information only)",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1302",
    "title": "Root boot code others can change",
    "tier": "Root",
    "severity": "Notice",
    "failsWhen": "a boot script root runs, or a folder holding it, is not owned by root or is writable by others",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "INTG-1303",
    "title": "Programs staged in shared temp",
    "tier": "Root",
    "severity": "Notice",
    "failsWhen": "a script or executable is staged in /data/local/tmp",
    "category": "Device integrity",
    "betaAdded": false
  },
  {
    "id": "ACCS-2001",
    "title": "Secure lock screen",
    "tier": "Base",
    "severity": "Critical",
    "failsWhen": "no PIN, pattern or password is set",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2002",
    "title": "Screen timeout",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the screen stays on for more than 2 minutes",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2003",
    "title": "Password visibility",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "typed password characters are shown",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2004",
    "title": "Lock screen notifications",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "notification content is visible while the phone is locked",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2005",
    "title": "Stay awake while charging",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the screen never turns off, so never locks, while charging",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2006",
    "title": "Lock after screen timeout",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the phone stays unlocked for more than 30 seconds after the screen turns off",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2007",
    "title": "Screen lock strength (Android 10+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the screen lock is a pattern or a PIN with repeated or ordered digits",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2008",
    "title": "Notification history (Android 11+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "notification history is on, keeping 24 hours of notification text",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2009",
    "title": "Biometric unlock strength (Android 11+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the only biometric unlock set up is weak (Class 2), such as most camera-only face unlock",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2010",
    "title": "Developer options",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "developer options are on",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2011",
    "title": "USB debugging",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "adb over USB is on",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2012",
    "title": "Wireless debugging (Android 11+)",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "adb over Wi-Fi is on",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2013",
    "title": "USB debugging authorization timeout (Android 11+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "computers allowed for USB debugging keep their access for more than 7 days without connecting, or for good",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2020",
    "title": "Remote lock and erase",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "no app or known service can lock and erase the phone remotely",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2101",
    "title": "Smart Lock and Extend Unlock",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a trust agent such as Smart Lock can keep the phone unlocked",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2201",
    "title": "SIM card PIN (Android 11+)",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "a SIM in use has its PIN turned off",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2202",
    "title": "Device controls on the lock screen (Android 13+)",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "device controls can be used without unlocking the phone",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "ACCS-2301",
    "title": "Computers trusted for USB debugging",
    "tier": "Root",
    "severity": "Notice",
    "failsWhen": "a computer is trusted for USB debugging",
    "category": "Access control",
    "betaAdded": false
  },
  {
    "id": "APPS-4001",
    "title": "Accessibility services",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "any accessibility service is enabled (a warning when its app came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4002",
    "title": "Device admin apps",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "a device admin you installed, or a device or profile owner, is active (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4003",
    "title": "Debuggable apps",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an installed app is debuggable",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4004",
    "title": "Apps from unknown sources",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app came from outside a known app store",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4005",
    "title": "Notification access",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app you installed can read all notifications (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4006",
    "title": "Keyboard apps",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "a third-party keyboard is enabled",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4007",
    "title": "Apps built for old Android",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "a user app targets Android 8.1 (API 27) or older",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4008",
    "title": "Apps that can read your SMS or call log",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app other than your SMS and phone apps, or one of those installed from outside an app store, can read SMS or the call log (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4009",
    "title": "Apps that can send SMS",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app other than your SMS app can send SMS (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4010",
    "title": "Autofill service (Android 9+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an autofill service from an app you installed is selected (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4011",
    "title": "Digital assistant app",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "the digital assistant is an app you installed (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4012",
    "title": "Apps with location all the time (Android 10+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app you installed may use location all the time (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4013",
    "title": "Apps that skip battery optimization",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "an app you installed may skip battery optimization (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4014",
    "title": "Google Play services",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "Google Play services is built into the system, with privileged access (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4015",
    "title": "App scanning (Play Protect)",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "the install-time app verifier is turned off, or Play Protect's \"Scan apps\" switch is",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4016",
    "title": "Apps with Shizuku access",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app other than Droynis may use Shizuku (a warning when it came from outside an app store, or Shizuku runs as root)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4017",
    "title": "Profiles this scan doesn't cover",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "another profile shares this user, Droynis doesn't run in the phone's main user, or (ADB tier and up) the phone has another user or profile (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4018",
    "title": "Apps that allow unencrypted connections",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "an app you installed has network access and declares that it may connect without encryption (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4019",
    "title": "Apps that can run commands through Termux or Tasker",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "another app may run commands in Termux or start Tasker tasks (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": true
  },
  {
    "id": "APPS-4020",
    "title": "Apps with system permissions granted over adb",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an app you installed holds WRITE_SECURE_SETTINGS, READ_LOGS, DUMP or INTERACT_ACROSS_USERS, which only adb, Shizuku or root can grant",
    "category": "Apps and permissions",
    "betaAdded": true
  },
  {
    "id": "APPS-4102",
    "title": "Apps that can draw over other apps (Android 10+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a user app may display over other apps",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4103",
    "title": "Apps with access to all files (Android 11+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a user app has all files access",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4104",
    "title": "Apps that can install other apps (Android 10+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a user app other than a known app store may install apps",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4105",
    "title": "Apps with usage access (Android 10+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a user app has usage access",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4106",
    "title": "Apps that can change system settings (Android 10+)",
    "tier": "ADB",
    "severity": "Info",
    "failsWhen": "a user app may change system settings (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4107",
    "title": "Apps that can manage your media (Android 12+)",
    "tier": "ADB",
    "severity": "Info",
    "failsWhen": "a user app may change or delete media without asking (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4109",
    "title": "Apps that keep their permissions while unused (Android 11+)",
    "tier": "ADB",
    "severity": "Info",
    "failsWhen": "a user app is exempt from having its permissions removed while unused (information only)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4201",
    "title": "Passkey and password providers (Android 14+)",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "a passkey or password provider from an app you installed is turned on (a warning when it came from outside an app store)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4202",
    "title": "Clipboard access alerts (Android 12+)",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "\"Show clipboard access\" is off, so apps read the clipboard silently",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4301",
    "title": "Apps with root access",
    "tier": "Root",
    "severity": "Warning",
    "failsWhen": "an app other than Droynis may get root",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4302",
    "title": "Root access over ADB",
    "tier": "Root",
    "severity": "Warning",
    "failsWhen": "Magisk grants root to the ADB shell (Superuser access includes ADB; the default)",
    "category": "Apps and permissions",
    "betaAdded": false
  },
  {
    "id": "APPS-4303",
    "title": "Apps allowed to text premium numbers",
    "tier": "Root",
    "severity": "Warning",
    "failsWhen": "an app's Premium SMS access is set to Always allow",
    "category": "Apps and permissions",
    "betaAdded": true
  },
  {
    "id": "SUSP-5001",
    "title": "Apps hiding from the app drawer",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an installed app turned its app drawer icon off, or shows a blank name or a transparent icon (critical when it came from outside an app store, or has accessibility, device admin or notification access)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5002",
    "title": "Hidden apps set up to run in the background",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an app that hides from the app drawer, or one without an icon from outside an app store, declares it starts at boot, runs foreground services, draws over other apps, shows full-screen pop-ups or skips battery limits (critical when it hides and came from outside an app store)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5003",
    "title": "Hidden apps showing screens",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an app that hides from the app drawer, or one without an icon from outside an app store, brought its own screen to the front in the last 7 days (critical when it hides and came from outside an app store)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5004",
    "title": "Apps installed by another app",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an app was installed by another app you installed that isn't an app store or an installer tool",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5005",
    "title": "Apps with banking-trojan permissions",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an installed app declares an accessibility service and asks for SMS and to draw over other apps (critical when it came from outside an app store or its accessibility service is on)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5006",
    "title": "Apps signed with a debug or test key",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "a user app is signed with Android's debug key or a public test key (warning for a test key, or a debug key on an app that isn't debuggable)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5007",
    "title": "Known stalkerware and monitoring apps",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "an app you installed has the package name or signing key of an app on Echap's Stalkerware Indicators list (critical for stalkerware, warning for a monitoring app that doesn't hide)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5008",
    "title": "Apps using a built-in app's name",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "an app from outside an app store shows the same name as an app that came with the phone (a warning when that app is a core one, such as Settings or Google Play services)",
    "category": "Suspicious apps",
    "betaAdded": true
  },
  {
    "id": "SUSP-5009",
    "title": "Apps posing as an app store",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "a user app uses the package name of an app store whose signing keys Droynis knows, but none of them (critical when it has installed other apps)",
    "category": "Suspicious apps",
    "betaAdded": true
  },
  {
    "id": "SUSP-5010",
    "title": "Screen being recorded or shared",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "the screen is being recorded or shared while Droynis scans (Android 15+), or an app you installed shows the screen on a display of its own (critical when that app came from outside an app store)",
    "category": "Suspicious apps",
    "betaAdded": true
  },
  {
    "id": "SUSP-5101",
    "title": "Hidden apps running in the background (Android 10+)",
    "tier": "ADB",
    "severity": "Warning",
    "failsWhen": "an app that hides from the app drawer, or one without an icon from outside an app store, runs a service it started, or started a foreground service or drew over other apps in the last 7 days (critical when it hides and came from outside an app store)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5102",
    "title": "Background camera, microphone and location use (Android 10+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a user app used the camera, microphone or location from the background in the last 7 days (warning for camera or microphone)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5103",
    "title": "Apps that can record the screen without asking (Android 10+)",
    "tier": "ADB",
    "severity": "Warning",
    "failsWhen": "a user app may record or cast the screen without asking",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "SUSP-5104",
    "title": "Background SMS, call log and contacts use (Android 10+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a user app read SMS, the call log or contacts, or received SMS, from the background in the last 7 days (warning when it came from outside an app store)",
    "category": "Suspicious apps",
    "betaAdded": false
  },
  {
    "id": "NETW-3001",
    "title": "Private DNS (Android 9+)",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "DNS isn't encrypted and no VPN is active",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3002",
    "title": "VPN",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "no VPN is active",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3003",
    "title": "User CA certificates",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "a user-installed CA certificate can intercept TLS",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3004",
    "title": "Bluetooth",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "Bluetooth is on",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3005",
    "title": "Wi-Fi security (Android 12+)",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "the phone is on an open or WEP Wi-Fi network without a VPN",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3006",
    "title": "NFC",
    "tier": "Base",
    "severity": "Info",
    "failsWhen": "NFC is on",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3007",
    "title": "HTTP proxy",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "web traffic on Wi-Fi, mobile data or another network goes through an HTTP proxy",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3008",
    "title": "Location",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "Location is on",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3009",
    "title": "Wi-Fi and Bluetooth scanning",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "Wi-Fi or Bluetooth scanning is on",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3010",
    "title": "2G mobile networks",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "a SIM in use may connect to 2G networks",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3011",
    "title": "Secure NFC (Android 10+)",
    "tier": "Base",
    "severity": "Notice",
    "failsWhen": "NFC is on and works while the phone is locked",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3012",
    "title": "Added system CA certificates",
    "tier": "Base",
    "severity": "Warning",
    "failsWhen": "a CA certificate was added to the system store, which every app trusts (by a root module or a modified system)",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3101",
    "title": "Wi-Fi MAC randomization (Android 10+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "the current Wi-Fi connection or a saved network uses the phone's own MAC address",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3102",
    "title": "Open Wi-Fi networks that join automatically (Android 12+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a saved open, Enhanced Open or WEP network joins automatically",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3103",
    "title": "Hotspot security (Android 14+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "the hotspot has no password (a warning), or doesn't turn off by itself when no device is connected",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3104",
    "title": "Hidden Wi-Fi networks (Android 12+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a saved Wi-Fi network is hidden, so the phone calls out its name when it looks for Wi-Fi",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3105",
    "title": "Saved Wi-Fi networks with broken encryption (Android 12+)",
    "tier": "ADB",
    "severity": "Notice",
    "failsWhen": "a saved Wi-Fi network uses WEP",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3106",
    "title": "Call forwarding",
    "tier": "ADB",
    "severity": "Warning",
    "failsWhen": "a SIM in use forwards all calls to another number",
    "category": "Network and radios",
    "betaAdded": true
  },
  {
    "id": "NETW-3201",
    "title": "Always-on VPN lockdown",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "an always-on VPN lets traffic out while it is down",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3202",
    "title": "Mobile network encryption (Android 14+)",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "the phone accepts mobile connections without encryption (Require encryption is off)",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3203",
    "title": "Mobile network security alerts (Android 15+)",
    "tier": "Shizuku",
    "severity": "Notice",
    "failsWhen": "the phone doesn't warn about signs of a fake cell tower (Network notifications are off)",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3301",
    "title": "Apps listening on the network",
    "tier": "Root",
    "severity": "Notice",
    "failsWhen": "a user app accepts connections from the network",
    "category": "Network and radios",
    "betaAdded": false
  },
  {
    "id": "NETW-3302",
    "title": "Quick Share visibility",
    "tier": "Root",
    "severity": "Notice",
    "failsWhen": "Quick Share (Nearby Share) is visible to everyone nearby",
    "category": "Network and radios",
    "betaAdded": true
  }
];
