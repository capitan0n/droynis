# Droynis checks

<!-- Generated from the check definitions by CatalogDocTest. Don't edit by hand: after
     changing a check, run UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test -->

Every check Droynis runs, by privilege tier and category: 43 checks.

A check passes only after reading a passing value; anything it can't establish is Unknown or
N/A, never Passed.

Severity sets a failed check's weight in the score: critical 10, warning 5, notice 2, info 0.
Any critical failure caps the score at 40, and muted checks don't count.

| Tier | Checks |
|---|---|
| [Base](#base-tier) | 34 |
| [ADB](#adb-tier) | 7 |
| [Shizuku](#shizuku-tier) | 2 |
| Root | planned |

## Base tier

Public Android APIs only. These checks run on every phone, with no setup and no extra permissions.

| ID | Check | Severity | Fails when |
|---|---|---|---|
| [INTG-1010](#intg-1010-security-patch-age) | Security patch age | Warning | the security patch is older than 90 days (critical when over a year old) |
| [INTG-1020](#intg-1020-storage-encryption) | Storage encryption | Critical | storage is unencrypted, or encrypted only with the default key |
| [INTG-1030](#intg-1030-advanced-protection) | Advanced Protection (Android 16+) | Info | Advanced Protection is off |
| [INTG-1040](#intg-1040-bootloader-lock) | Bootloader lock | Critical | the bootloader is unlocked or verified boot isn't passing (hardware key attestation, boot properties as a fallback) |
| [INTG-1041](#intg-1041-oem-unlocking) | OEM unlocking | Notice | the OEM unlocking switch is on |
| [INTG-1050](#intg-1050-root-access) | Root access | Critical | an su binary, a root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found |
| [INTG-1060](#intg-1060-android-build) | Android build | Warning | it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1 |
| [INTG-1070](#intg-1070-webview-updates) | WebView updates | Warning | WebView hasn't been updated for more than 60 days |
| [ACCS-2001](#accs-2001-secure-lock-screen) | Secure lock screen | Critical | no PIN, pattern or password is set |
| [ACCS-2002](#accs-2002-screen-timeout) | Screen timeout | Notice | the screen stays on for more than 2 minutes |
| [ACCS-2003](#accs-2003-password-visibility) | Password visibility | Notice | typed password characters are shown |
| [ACCS-2004](#accs-2004-lock-screen-notifications) | Lock screen notifications | Notice | notification content is visible while the phone is locked |
| [ACCS-2005](#accs-2005-stay-awake-while-charging) | Stay awake while charging | Notice | the screen never turns off, so never locks, while charging |
| [ACCS-2006](#accs-2006-lock-after-screen-timeout) | Lock after screen timeout | Notice | the phone stays unlocked for more than 30 seconds after the screen turns off |
| [ACCS-2010](#accs-2010-developer-options) | Developer options | Notice | developer options are on |
| [ACCS-2011](#accs-2011-usb-debugging) | USB debugging | Warning | adb over USB is on |
| [ACCS-2012](#accs-2012-wireless-debugging) | Wireless debugging (Android 11+) | Warning | adb over Wi-Fi is on |
| [ACCS-2020](#accs-2020-remote-lock-and-erase) | Remote lock and erase | Notice | no app or known service can lock and erase the phone remotely |
| [APPS-4001](#apps-4001-accessibility-services) | Accessibility services | Notice | any accessibility service is enabled |
| [APPS-4002](#apps-4002-device-admin-apps) | Device admin apps | Notice | any device admin is active |
| [APPS-4003](#apps-4003-debuggable-apps) | Debuggable apps | Warning | an installed app is debuggable |
| [APPS-4004](#apps-4004-apps-from-unknown-sources) | Apps from unknown sources | Notice | an app came from outside a known app store |
| [APPS-4005](#apps-4005-notification-access) | Notification access | Notice | an app can read all notifications |
| [APPS-4006](#apps-4006-keyboard-apps) | Keyboard apps | Notice | a third-party keyboard is enabled |
| [APPS-4007](#apps-4007-apps-built-for-old-android) | Apps built for old Android | Notice | a user app targets Android 8.1 (API 27) or older |
| [NETW-3001](#netw-3001-private-dns) | Private DNS (Android 9+) | Warning | DNS isn't encrypted and no VPN is active |
| [NETW-3002](#netw-3002-vpn) | VPN | Info | no VPN is active |
| [NETW-3003](#netw-3003-user-ca-certificates) | User CA certificates | Warning | a user-installed CA certificate can intercept TLS |
| [NETW-3004](#netw-3004-bluetooth) | Bluetooth | Notice | Bluetooth is on |
| [NETW-3005](#netw-3005-wi-fi-security) | Wi-Fi security (Android 12+) | Warning | the phone is on an open or WEP Wi-Fi network without a VPN |
| [NETW-3006](#netw-3006-nfc) | NFC | Info | NFC is on |
| [NETW-3007](#netw-3007-http-proxy) | HTTP proxy | Warning | web traffic goes through an HTTP proxy |
| [NETW-3008](#netw-3008-location) | Location | Notice | Location is on |
| [NETW-3009](#netw-3009-wi-fi-and-bluetooth-scanning) | Wi-Fi and Bluetooth scanning | Notice | Wi-Fi or Bluetooth scanning is on |

### Device integrity

#### INTG-1010 Security patch age

Warning · Android 8.0 and later · fails when the security patch is older than 90 days (critical when over a year old)

The security patch level is the date of the newest Android security bulletin the OS says it includes. Since 2025 most fixes ship in quarterly releases, so a level older than about 90 days has missed at least one, and publicly known vulnerabilities stay open.

**What to do:** Install pending system updates (Settings › System › Software update; the location varies by vendor). If the vendor no longer ships updates, the device is end-of-life: plan to replace it or move to a maintained OS that supports relocking the bootloader.

#### INTG-1020 Storage encryption

Critical · Android 8.0 and later · fails when storage is unencrypted, or encrypted only with the default key

Encryption keeps your data unreadable if the phone is lost, stolen or its storage is copied. Every device that shipped with Android 10 or later must encrypt each user's data with keys tied to the screen lock.

**What to do:** Set a PIN or password, since the encryption keys are tied to it. If storage is not encrypted at all, the device or its firmware cannot protect data at rest: back up your data and plan to replace it.

#### INTG-1030 Advanced Protection

Info · Android 16 and later · fails when Advanced Protection is off

Advanced Protection (Android 16+) switches on Android's strictest defenses at once, for example blocking app installs from unknown sources and 2G connections. It is meant for people at higher risk, such as journalists and activists.

**What to do:** If you are at higher risk, turn it on under Settings › Security & privacy › Advanced Protection. It also blocks installing apps from unknown sources, including the F-Droid client.

#### INTG-1040 Bootloader lock

Critical · Android 8.0 and later · fails when the bootloader is unlocked or verified boot isn't passing (hardware key attestation, boot properties as a fallback)

A locked bootloader starts only an operating system signed by the phone's vendor, or by a relockable OS such as GrapheneOS. Unlocked, anyone holding the phone can boot a modified system that captures your PIN or your data the next time you unlock it, and verified boot no longer stops persistent malware.

**What to do:** Relock the bootloader only if the installed OS supports it: stock firmware, or an OS with its own verified-boot key such as GrapheneOS or CalyxOS. Relocking wipes the phone, and relocking with an unsupported custom OS can leave it unbootable. With the phone in fastboot mode, run this from a computer:

#### INTG-1041 OEM unlocking

Notice · Android 8.0 and later · fails when the OEM unlocking switch is on

While OEM unlocking is allowed, the bootloader can be unlocked from a computer in minutes. Unlocking wipes your data, but it also defeats Factory Reset Protection, so a stolen phone can be reset and resold, and it is the first step to installing a modified system.

**What to do:** Turn off OEM unlocking in Developer options. The switch is greyed out while the bootloader is unlocked or when the carrier does not allow unlocking.

#### INTG-1050 Root access

Critical · Android 8.0 and later · fails when an su binary, a root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found

Root lets any app you approve read every other app's data, log what you type and hide itself from the system. It also switches off much of Android's app sandbox. Root can be hidden, so a clean result means no signs were found, not that the phone cannot be rooted.

**What to do:** If you did not root this phone yourself, back up your data and reinstall the official firmware. If you did, remove the root manager when you no longer need it and grant root only to apps you trust.

#### INTG-1060 Android build

Warning · Android 8.0 and later · fails when it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1

Phones ship "user" builds signed with the vendor's private keys. A userdebug or eng build lets adb run as root, and a build signed with the public AOSP test keys lets anyone sign an app or update that the system trusts as its own.

**What to do:** Install the official firmware, or a maintained OS that publishes signed user builds.

#### INTG-1070 WebView updates

Warning · Android 8.0 and later · fails when WebView hasn't been updated for more than 60 days

Most apps show web pages through the system WebView, a full browser engine that receives security fixes every few weeks. Browser engines are a favourite target for exploits, so an outdated WebView puts every app that uses it at risk.

**What to do:** Update Android System WebView, or the browser that provides it (Chrome, Vanadium…), from your app store, and install pending system updates.

### Access control

#### ACCS-2001 Secure lock screen

Critical · Android 8.0 and later · fails when no PIN, pattern or password is set

Without a PIN, pattern or password, anyone holding the device can use it, and the encryption of your data is not tied to any secret you know. Biometrics and apps that protect their keys with your screen lock depend on it too.

**What to do:** Set a PIN or password. A PIN of 6 or more digits or an alphanumeric password is much stronger than a pattern.

#### ACCS-2002 Screen timeout

Notice · Android 8.0 and later · fails when the screen stays on for more than 2 minutes

The phone locks itself only after the screen turns off. A long timeout leaves an unlocked phone open to anyone nearby, for example on a desk or table.

**What to do:** Set Screen timeout to 1 minute or less (Settings › Display).

#### ACCS-2003 Password visibility

Notice · Android 8.0 and later · fails when typed password characters are shown

With "Show passwords" on, each character you type into a password field stays visible for a moment. Someone looking over your shoulder, a screen recording or a malicious accessibility service can pick it up.

**What to do:** Turn off "Show passwords" (Settings › Privacy on most phones, Settings › Security on older ones).

#### ACCS-2004 Lock screen notifications

Notice · Android 8.0 and later · fails when notification content is visible while the phone is locked

Notifications on the lock screen can be read without unlocking the phone. Message previews and one-time login codes are then visible to anyone who picks it up.

**What to do:** In the notification settings, set notifications on the lock screen to hide sensitive content, or not to show at all.

#### ACCS-2005 Stay awake while charging

Notice · Android 8.0 and later · fails when the screen never turns off, so never locks, while charging

With "Stay awake" on, the screen never turns off while the phone charges, so it never locks either. Anyone who picks up a charging phone that was left unlocked gets in without the PIN.

**What to do:** Turn off "Stay awake" in Developer options.

#### ACCS-2006 Lock after screen timeout

Notice · Android 8.0 and later · fails when the phone stays unlocked for more than 30 seconds after the screen turns off

When the screen turns off by itself, Android waits this long before it asks for your PIN again. Anyone who picks the phone up in that window gets in without it, which is how many phone thefts work. The power button can lock at once, but apps can't read that setting.

**What to do:** Under Settings › Security › Screen lock (gear icon), set Lock after screen timeout to 30 seconds or less, and turn on "Power button instantly locks".

#### ACCS-2010 Developer options

Notice · Android 8.0 and later · fails when developer options are on

Developer options unlock debugging features such as USB and wireless debugging, mock locations and OEM unlocking. They are not meant for everyday use, and keeping them hidden lowers the chance of a risky switch being left on.

**What to do:** Turn Developer options off with the switch at the top of the Developer options screen. Permissions granted to Droynis with adb stay granted.

#### ACCS-2011 USB debugging

Warning · Android 8.0 and later · fails when adb over USB is on

With USB debugging on, any computer you have authorized can install apps, grant them permissions, read shared storage and capture the screen through adb. It widens what someone with physical access, or with control of a computer you once trusted, can do.

**What to do:** Turn off USB debugging in Developer options and tap "Revoke USB debugging authorizations". Permissions granted to Droynis with adb stay granted afterwards.

#### ACCS-2012 Wireless debugging

Warning · Android 11 and later · fails when adb over Wi-Fi is on

Wireless debugging exposes adb on the Wi-Fi network. Any computer you have paired can then install apps and control the phone over the network, without a cable.

**What to do:** Turn off Wireless debugging in Developer options and remove paired devices you no longer use. Android also turns it off when you leave the Wi-Fi network.

#### ACCS-2020 Remote lock and erase

Notice · Android 8.0 and later · fails when no app or known service can lock and erase the phone remotely

If the phone is lost or stolen, a find-my-device service lets you locate, lock and erase it from another device. Android doesn't let apps see whether Google's or the phone maker's service is turned on, so Droynis looks for an app allowed to lock and erase the phone, and for the built-in services it knows.

**What to do:** Turn on your phone's find-my-device service: with Google services, Settings › Google › All services › Find Hub, and Theft protection next to it; on Samsung, Find My Mobile. Without Google services, the open-source FMD app (on F-Droid) can locate, lock and erase the phone.

### Apps and permissions

#### APPS-4001 Accessibility services

Notice · Android 8.0 and later · fails when any accessibility service is enabled

An accessibility service can read everything on screen and tap on your behalf. Screen readers and password managers need this, but it is also the favorite tool of Android banking trojans.

**What to do:** Keep only services you recognize and still use; turn the others off under Settings › Accessibility.

#### APPS-4002 Device admin apps

Notice · Android 8.0 and later · fails when any device admin is active

Device admin apps can lock or wipe the phone and enforce password rules; a device or profile owner can manage it completely. Find-my-device and work profiles use this legitimately; anything you do not recognize deserves a closer look.

**What to do:** Review them under Settings › Security › Device admin apps (the location varies by vendor) and deactivate the ones you do not need.

#### APPS-4003 Debuggable apps

Warning · Android 8.0 and later · fails when an installed app is debuggable

A debuggable app lets anyone with adb access read its private data and run code inside it. Store builds are never debuggable, so a debuggable app is a development build or has been modified.

**What to do:** Uninstall debuggable apps you are not developing yourself, or replace them with the official release. Droynis itself is excluded from this check.

#### APPS-4004 Apps from unknown sources

Notice · Android 8.0 and later · fails when an app came from outside a known app store

Apps installed from a downloaded file or over adb skip the review an app store performs and usually do not update automatically. That is fine for apps you trust, but each one is worth knowing about.

**What to do:** Review the list and uninstall apps you do not recognize. Prefer a store such as F-Droid, Accrescent or Google Play, which also keeps the apps updated.

#### APPS-4005 Notification access

Notice · Android 8.0 and later · fails when an app can read all notifications

An app with notification access reads every notification as it arrives, including message previews and one-time login codes, and can act on them. Watch and automation apps need it; any other app that has it deserves a second look.

**What to do:** Under Special app access › Notification access (the name varies by vendor), turn it off for apps that do not need it.

#### APPS-4006 Keyboard apps

Notice · Android 8.0 and later · fails when a third-party keyboard is enabled

A keyboard sees everything you type, passwords and private messages included, and some send it to the cloud for suggestions. Keyboards built into the system come with the phone's trust; any other one should come from a developer you trust.

**What to do:** Disable keyboards you do not use under Settings › System › Keyboard (the path varies). An open-source keyboard that works offline keeps your typing on the phone.

#### APPS-4007 Apps built for old Android

Notice · Android 8.0 and later · fails when a user app targets Android 8.1 (API 27) or older

Android applies many protections only to apps that declare a recent target version, for example scoped storage and limits on reading device identifiers. Apps built for Android 8.1 or older skip them and are usually no longer maintained; Android 14 even refuses to install apps built for Android 5.1 or older.

**What to do:** Update these apps, or replace the ones that are no longer maintained.

### Network and radios

#### NETW-3001 Private DNS

Warning · Android 9 and later · fails when DNS isn't encrypted and no VPN is active

Without Private DNS, every website and app domain you look up is sent in plain text. The Wi-Fi owner or the mobile carrier can log those lookups or answer them with fake ones. Private DNS (DNS over TLS) encrypts them.

**What to do:** Open Private DNS (Settings › Network & internet; the location varies by vendor), choose "Private DNS provider hostname" and enter a privacy-respecting resolver such as dns.quad9.net.

#### NETW-3002 VPN

Info · Android 8.0 and later · fails when no VPN is active

A VPN encrypts traffic between this phone and the VPN server, hiding it from the local network and the carrier. It moves that trust to the VPN provider, so pick one with an audited no-logs policy, or host your own.

**What to do:** Use a trustworthy VPN, especially on public Wi-Fi. Under Settings › Network & internet › VPN you can also turn on "Always-on VPN" and "Block connections without VPN".

#### NETW-3003 User CA certificates

Warning · Android 8.0 and later · fails when a user-installed CA certificate can intercept TLS

An installed certificate authority can be used to decrypt the TLS traffic of apps that trust user certificates, for example on a school or company network that inspects traffic. One you did not knowingly install is a red flag.

**What to do:** Under Settings › Security › Encryption & credentials › Trusted credentials › User, remove certificates you do not need (the location varies by vendor).

#### NETW-3004 Bluetooth

Notice · Android 8.0 and later · fails when Bluetooth is on

A radio that is on can be attacked: Bluetooth flaws such as BlueBorne and BLUFFS let nearby attackers reach a phone without pairing. Leaving it on also makes the device easier to notice and track nearby.

**What to do:** Turn Bluetooth off when you are not using headphones, a watch or a car.

#### NETW-3005 Wi-Fi security

Warning · Android 12 and later · fails when the phone is on an open or WEP Wi-Fi network without a VPN

On an open or WEP Wi-Fi network anyone in range can record the traffic and set up a look-alike network. HTTPS still protects page contents, but plain DNS lookups and badly written apps leak.

**What to do:** Avoid open and WEP networks or use a VPN on them, and forget saved open networks so the phone does not rejoin them by itself.

#### NETW-3006 NFC

Info · Android 8.0 and later · fails when NFC is on

NFC talks to cards, payment terminals and tags held a few centimeters away. The short range makes attacks rare, but switching it off when you do not pay by phone closes one more way in.

**What to do:** Turn NFC off if you do not use contactless payments, transit cards or NFC tags.

#### NETW-3007 HTTP proxy

Warning · Android 8.0 and later · fails when web traffic goes through an HTTP proxy

An HTTP proxy receives the web traffic of every app that honours it. A proxy you did not set up yourself, added by an app, a management profile or a network, can log the sites you visit and tamper with unencrypted pages.

**What to do:** If you do not recognise the proxy, remove it: open the Wi-Fi network's details and set Proxy to None.

#### NETW-3008 Location

Notice · Android 8.0 and later · fails when Location is on

With Location on, every app you allowed can see where you are, and the phone's location services may keep collecting Wi-Fi and cell data in the background. Turning it off when you don't need it is the simplest way to stop being tracked.

**What to do:** Turn Location off in Quick Settings when you don't need it. Under Settings › Location › App location permissions, keep "Allow all the time" only for apps that really need it.

#### NETW-3009 Wi-Fi and Bluetooth scanning

Notice · Android 8.0 and later · fails when Wi-Fi or Bluetooth scanning is on

With these on, the phone keeps scanning for Wi-Fi networks and Bluetooth devices even when you turn Wi-Fi and Bluetooth off, to help locate you. The radios stay active, so turning them off doesn't close their attack surface or stop location from working.

**What to do:** Turn off Wi-Fi scanning and Bluetooth scanning under Settings › Location › Location services (on older Android: Location › Scanning).

## ADB tier

Two read-only permissions, granted once from a computer with adb, unlock checks that public Android APIs can't do. Until then these checks show as N/A and don't change the score. The Shizuku tier covers them too, without the grants.

Turn on USB debugging, connect the phone to a computer with adb, run:

```sh
adb shell pm grant io.github.capitan0n.droynis android.permission.DUMP
adb shell pm grant io.github.capitan0n.droynis android.permission.PACKAGE_USAGE_STATS
```

Then tap Scan again. The grants stay until `adb shell pm revoke …` or an uninstall.

| ID | Check | Severity | Fails when |
|---|---|---|---|
| [APPS-4101](#apps-4101-background-camera-microphone-and-location-use) | Background camera, microphone and location use (Android 10+) | Notice | a user app used the camera, microphone or location from the background in the last 7 days (warning for camera or microphone) |
| [APPS-4102](#apps-4102-apps-that-can-draw-over-other-apps) | Apps that can draw over other apps (Android 10+) | Notice | a user app may display over other apps |
| [APPS-4103](#apps-4103-apps-with-access-to-all-files) | Apps with access to all files (Android 11+) | Notice | a user app has all files access |
| [APPS-4104](#apps-4104-apps-that-can-install-other-apps) | Apps that can install other apps (Android 10+) | Notice | a user app other than a known app store may install apps |
| [APPS-4105](#apps-4105-apps-with-usage-access) | Apps with usage access (Android 10+) | Notice | a user app has usage access |
| [APPS-4106](#apps-4106-apps-that-can-change-system-settings) | Apps that can change system settings (Android 10+) | Info | a user app may change system settings (information only) |
| [APPS-4107](#apps-4107-apps-that-can-manage-your-media) | Apps that can manage your media (Android 12+) | Info | a user app may change or delete media without asking (information only) |

### Apps and permissions

#### APPS-4101 Background camera, microphone and location use

Notice · Android 10 and later · fails when a user app used the camera, microphone or location from the background in the last 7 days (warning for camera or microphone)

Lists user-installed apps that used the camera, the microphone or your location while you were not using them, in the last 7 days. Spyware works this way; so do fitness, navigation and smart-home apps, so check that each one is expected. Android keeps this record in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** For each app listed, open Settings › Apps › the app › Permissions. Set Location to "Allow only while using the app" or "Don't allow", and remove Camera and Microphone from apps that don't need them. Uninstall apps you don't recognize.

#### APPS-4102 Apps that can draw over other apps

Notice · Android 10 and later · fails when a user app may display over other apps

Apps allowed to "Display over other apps" (on Samsung: "Appear on top") can put windows on top of anything on the screen. Chat bubbles and screen filters use this; malware uses it to cover real apps with fake login forms or to trick you into tapping something else. Android keeps this switch in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Display over other apps and turn it off for every app listed that doesn't need it. Uninstall apps you don't recognize.

#### APPS-4103 Apps with access to all files

Notice · Android 11 and later · fails when a user app has all files access

"All files access" lets an app read, change and delete every file in shared storage: photos, downloads and documents, whatever app made them. File managers and backup apps need it; most other apps don't. Android keeps this switch in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › All files access and turn it off for every app listed that doesn't manage or back up your files.

#### APPS-4104 Apps that can install other apps

Notice · Android 10 and later · fails when a user app other than a known app store may install apps

Apps allowed to "Install unknown apps" can offer you APK files to install. You still confirm each one, but a malicious or hacked app with this right can push malware at you. App stores need it and don't count. Android keeps this switch in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Install unknown apps and turn it off for the apps listed. Turn it on again only while you install something you trust.

#### APPS-4105 Apps with usage access

Notice · Android 10 and later · fails when a user app has usage access

"Usage access" (on Samsung: "Usage data access") shows an app which other apps you use, when and for how long. Launchers and digital wellbeing apps use it; so does stalkerware, to follow what you do on the phone. Android keeps this switch in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Usage access and turn it off for every app listed that doesn't need it.

#### APPS-4106 Apps that can change system settings

Info · Android 10 and later · fails when a user app may change system settings (information only)

"Modify system settings" (on Samsung: "Change system settings") lets an app change everyday settings such as brightness, ringtone and screen timeout. It can't reach security settings, so this check is for your information and doesn't count in the score. Android keeps this switch in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Modify system settings and turn it off for apps you don't expect there.

#### APPS-4107 Apps that can manage your media

Info · Android 12 and later · fails when a user app may change or delete media without asking (information only)

"Media management" (on Samsung: "Manage media") lets an app that can see your photos, videos and audio also change, move or delete them without asking you each time. Gallery apps use it. This check is for your information and doesn't count in the score. Android keeps this switch in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Media management apps and turn it off for apps that don't organize your media.

## Shizuku tier

[Shizuku](https://github.com/RikkaApps/Shizuku) is an open-source app that gives other apps the rights adb has, without a computer once it runs. Through it Droynis starts a small shell that runs only a fixed list of read-only commands. It reads what Android hides from apps, such as the real USB debugging state on Android 17, and also runs every ADB-tier check.

1. Install Shizuku and start it: with Wireless debugging on Android 11 and later, or from a
   computer with adb. Shizuku's own guide shows each step.
2. In Droynis open ⋮ › Check catalog › Shizuku and tap Allow access.
3. Tap Scan again. After a reboot, start Shizuku again; to take access back, turn Droynis off in
   Shizuku's list of authorized apps.

| ID | Check | Severity | Fails when |
|---|---|---|---|
| [INTG-1201](#intg-1201-selinux-mode) | SELinux mode | Critical | SELinux is permissive or disabled |
| [NETW-3201](#netw-3201-always-on-vpn-lockdown) | Always-on VPN lockdown | Notice | an always-on VPN lets traffic out while it is down |

### Device integrity

#### INTG-1201 SELinux mode

Critical · Android 8.0 and later · fails when SELinux is permissive or disabled

SELinux confines every app and system service to what its policy allows, so a bug in one of them can't take over the whole phone. Production Android always enforces it; a permissive or disabled SELinux usually means a modified kernel or ROM. Apps can't read the mode, but the shell user Shizuku runs as can.

**What to do:** Settings can't turn SELinux back on. Install firmware that keeps it enforcing, such as the manufacturer's stock firmware or a ROM whose kernel enforces SELinux.

### Network and radios

#### NETW-3201 Always-on VPN lockdown

Notice · Android 8.0 and later · fails when an always-on VPN lets traffic out while it is down

An always-on VPN starts with the phone and stays connected. Only with "Block connections without VPN" does traffic also stop while the VPN is down or reconnecting; without it, apps quietly use the normal network. Apps can't see which app is the always-on VPN, but the shell user Shizuku runs as can.

**What to do:** Open Settings › Network & internet › VPN, tap the gear next to your VPN, and turn on both "Always-on VPN" and "Block connections without VPN".

## Root tier

Planned, for phones that are already rooted: a fixed list of read-only commands run through the root manager. Rooting weakens Android's security model, so don't root a phone just to audit it.
