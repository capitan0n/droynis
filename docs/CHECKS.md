# Droynis checks

<!-- Generated from the check definitions by CatalogDocTest. Don't edit by hand: after
     changing a check, run UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test -->

Every check Droynis runs, by category and privilege tier: 91 checks.

A check passes only after reading a passing value; anything it can't establish is Unknown or
N/A, never Passed.

Severity sets a failed check's weight in the score: critical 10, warning 5, notice 2, info 0.
Any critical failure caps the score at 40, and muted checks don't count.
You can trust an app that needs a lot of access, such as a watch app: every check that lists apps
still lists it, but none counts it.

## Contents

- [Privilege tiers](#privilege-tiers)
  - [Base](#base-tier)
  - [ADB](#adb-tier)
  - [Shizuku](#shizuku-tier)
  - [Root](#root-tier)
- [Device integrity](#device-integrity): 16 checks
- [Access control](#access-control): 18 checks
- [Apps and permissions](#apps-and-permissions): 26 checks
- [Suspicious apps](#suspicious-apps): 11 checks
- [Network and radios](#network-and-radios): 20 checks

## Privilege tiers

Checks per category and tier. Each tier also runs the checks of the tiers before it.

| Category | [Base](#base-tier) | [ADB](#adb-tier) | [Shizuku](#shizuku-tier) | [Root](#root-tier) | All |
|---|---|---|---|---|---|
| [Device integrity](#device-integrity) | 11 | – | 2 | 3 | 16 |
| [Access control](#access-control) | 14 | 1 | 2 | 1 | 18 |
| [Apps and permissions](#apps-and-permissions) | 16 | 6 | 2 | 2 | 26 |
| [Suspicious apps](#suspicious-apps) | 7 | 4 | – | – | 11 |
| [Network and radios](#network-and-radios) | 12 | 4 | 3 | 1 | 20 |
| **All** | 60 | 15 | 9 | 7 | 91 |

### Base tier

Public Android APIs only. These checks run on every phone, with no setup and no extra permissions.

### ADB tier

Two read-only permissions, granted once from a computer with adb, unlock checks that public Android APIs can't do. Until then these checks show as N/A and don't change the score. The Shizuku tier covers them too, without the grants.

Turn on USB debugging, connect the phone to a computer with adb, run:

```sh
adb shell pm grant io.github.capitan0n.droynis android.permission.DUMP
adb shell pm grant io.github.capitan0n.droynis android.permission.PACKAGE_USAGE_STATS
```

Then tap Scan again. The grants stay until `adb shell pm revoke …` or an uninstall.

### Shizuku tier

[Shizuku](https://github.com/RikkaApps/Shizuku) is an open-source app that gives other apps the rights adb has, without a computer once it runs. Through it Droynis starts a small shell that runs only a fixed list of read-only commands. It reads what Android hides from apps, such as the real USB debugging state on Android 17, the SIM PIN lock and the Allow 2G switch, and also runs every ADB-tier check.

1. Install Shizuku and start it: with Wireless debugging on Android 11 and later, or from a
   computer with adb. Shizuku's own guide shows each step.
2. In Droynis open ⋮ › Check catalog › Shizuku and tap Allow access.
3. Tap Scan again. After a reboot, start Shizuku again; to take access back, turn Droynis off in
   Shizuku's list of authorized apps.

### Root tier

For phones that are already rooted. Once you turn it on, Droynis asks the root manager (Magisk, KernelSU, APatch…) for a root shell at each scan and runs only a fixed list of read-only commands. Root also runs every ADB and Shizuku check. Rooting weakens Android's security model, so don't root a phone just to audit it; root access (INTG-1050) stays a critical finding.

1. In Droynis open ⋮ › Check catalog › Root and tap Allow root access.
2. Allow Droynis when the root manager asks. Droynis scans again by itself.
3. To stop, tap Turn off in the same tab, and revoke Droynis in the root manager's Superuser list.

## Device integrity

| ID | Check | Severity | Fails when |
|---|---|---|---|
| **[Base](#base-tier)** | | | |
| [INTG-1010](#intg-1010-security-patch-age) | Security patch age | Warning | the security patch is older than 90 days (critical when over a year old) |
| [INTG-1011](#intg-1011-vendor-and-kernel-patch-level) | Vendor and kernel patch level | Warning | the vendor or kernel patch is more than 90 days older than Android's (critical beyond a year) |
| [INTG-1020](#intg-1020-storage-encryption) | Storage encryption | Critical | storage is unencrypted, or encrypted only with the default key |
| [INTG-1030](#intg-1030-advanced-protection) | Advanced Protection (Android 16+) | Info | Advanced Protection is off |
| [INTG-1040](#intg-1040-bootloader-lock) | Bootloader lock | Critical | the bootloader is unlocked or verified boot isn't passing (hardware key attestation, boot properties as a fallback) |
| [INTG-1041](#intg-1041-oem-unlocking) | OEM unlocking | Notice | the OEM unlocking switch is on |
| [INTG-1050](#intg-1050-root-access) | Root access | Critical | an su binary, a root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found |
| [INTG-1060](#intg-1060-android-build) | Android build | Warning | it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1 (critical when ro.adb.secure=0 lets adb in without authorization) |
| [INTG-1070](#intg-1070-webview-updates) | WebView updates | Warning | WebView hasn't been updated for more than 60 days, or its Chromium version is older than that |
| [INTG-1080](#intg-1080-time-since-restart) | Time since restart | Notice | the phone hasn't restarted for more than 7 days |
| [INTG-1090](#intg-1090-storage-space) | Storage space | Notice | more than 80% of the internal storage is in use |
| **[Shizuku](#shizuku-tier)** | | | |
| [INTG-1201](#intg-1201-selinux-mode) | SELinux mode | Critical | SELinux is permissive or disabled |
| [INTG-1202](#intg-1202-spoofed-boot-properties) | Spoofed boot properties | Warning | a security-relevant ro.boot.* property differs from the kernel command line (a props spoofer) |
| **[Root](#root-tier)** | | | |
| [INTG-1301](#intg-1301-root-modules) | Root modules | Info | an enabled root module is installed (information only) |
| [INTG-1302](#intg-1302-root-boot-code-others-can-change) | Root boot code others can change | Notice | a boot script root runs, or a folder holding it, is not owned by root or is writable by others |
| [INTG-1303](#intg-1303-programs-staged-in-shared-temp) | Programs staged in shared temp | Notice | a script or executable is staged in /data/local/tmp |

### INTG-1010 Security patch age

Warning · Base tier · Android 8.0 and later · fails when the security patch is older than 90 days (critical when over a year old)

The security patch level is the date of the newest Android security bulletin the OS says it includes. Since 2025 most fixes ship in quarterly releases, so a level older than about 90 days has missed at least one, and publicly known vulnerabilities stay open.

**What to do:** Install pending system updates (Settings › System › Software update; the location varies by vendor). If the vendor no longer ships updates, the device is end-of-life: plan to replace it or move to a maintained OS that supports relocking the bootloader.

### INTG-1011 Vendor and kernel patch level

Warning · Base tier · Android 8.0 and later · fails when the vendor or kernel patch is more than 90 days older than Android's (critical beyond a year)

Android's security patch date covers the parts Google ships. The kernel and the vendor image, with the drivers and the hardware layer, are patched separately, and the modem firmware is updated along with them. When they fall months behind Android's patch, as on custom ROMs that run on old firmware or phones whose maker updates only Android, their known holes stay open; kernel and GPU driver bugs are among the most exploited on Android.

**What to do:** Install every system update. On a custom ROM, flash the newest firmware (vendor and modem images) for your device, or move to a ROM that ships it. A phone whose maker stopped firmware updates can't be fully patched.

### INTG-1020 Storage encryption

Critical · Base tier · Android 8.0 and later · fails when storage is unencrypted, or encrypted only with the default key

Encryption keeps your data unreadable if the phone is lost, stolen or its storage is copied. Every device that shipped with Android 10 or later must encrypt each user's data with keys tied to the screen lock.

**What to do:** Set a PIN or password, since the encryption keys are tied to it. If storage is not encrypted at all, the device or its firmware cannot protect data at rest: back up your data and plan to replace it.

### INTG-1030 Advanced Protection

Info · Base tier · Android 16 and later · fails when Advanced Protection is off

Advanced Protection (Android 16+) switches on Android's strictest defenses at once, for example blocking app installs from unknown sources and 2G connections. It is meant for people at higher risk, such as journalists and activists.

**What to do:** If you are at higher risk, turn it on under Settings › Security & privacy › Advanced Protection. It also blocks installing apps from unknown sources, including the F-Droid client. GrapheneOS has no such switch, so this check doesn't apply there: it offers similar protections one by one under Settings › Security & privacy › Exploit protection.

### INTG-1040 Bootloader lock

Critical · Base tier · Android 8.0 and later · fails when the bootloader is unlocked or verified boot isn't passing (hardware key attestation, boot properties as a fallback)

A locked bootloader starts only an operating system signed by the phone's vendor, or by a relockable OS such as GrapheneOS. Unlocked, anyone holding the phone can boot a modified system that captures your PIN or your data the next time you unlock it, and verified boot no longer stops persistent malware.

**What to do:** Relock the bootloader only if the installed OS supports it: stock firmware, or an OS with its own verified-boot key such as GrapheneOS or CalyxOS. Relocking wipes the phone, and relocking with an unsupported custom OS can leave it unbootable. With the phone in fastboot mode, run this from a computer:

### INTG-1041 OEM unlocking

Notice · Base tier · Android 8.0 and later · fails when the OEM unlocking switch is on

While OEM unlocking is allowed, the bootloader can be unlocked from a computer in minutes. Unlocking wipes your data, but it also defeats Factory Reset Protection, so a stolen phone can be reset and resold, and it is the first step to installing a modified system.

**What to do:** Turn off OEM unlocking in Developer options. The switch is greyed out while the bootloader is unlocked or when the carrier does not allow unlocking. If Developer options are off, turn them on first: in About phone, tap Build number seven times.

### INTG-1050 Root access

Critical · Base tier · Android 8.0 and later · fails when an su binary, a root manager (Magisk, KernelSU, APatch…) or Xposed/LSPosed is found

Root lets any app you approve read every other app's data, log what you type and hide itself from the system. It also switches off much of Android's app sandbox. Root can be hidden, so a clean result means no signs were found, not that the phone cannot be rooted.

**What to do:** If you did not root this phone yourself, back up your data and reinstall the official firmware. If you did, remove the root manager when you no longer need it and grant root only to apps you trust.

### INTG-1060 Android build

Warning · Base tier · Android 8.0 and later · fails when it's a userdebug or eng build, signed with the public test keys, or ro.debuggable=1 (critical when ro.adb.secure=0 lets adb in without authorization)

Phones ship "user" builds signed with the vendor's private keys. A userdebug or eng build lets adb run as root, and a build signed with the public AOSP test keys lets anyone sign an app or update that the system trusts as its own. With ro.adb.secure=0, any computer plugged in while USB debugging is on gets adb without the "Allow USB debugging?" prompt, a critical finding.

**What to do:** Install the official firmware, or a maintained OS that publishes signed user builds.

### INTG-1070 WebView updates

Warning · Base tier · Android 8.0 and later · fails when WebView hasn't been updated for more than 60 days, or its Chromium version is older than that

Most apps show web pages through the system WebView, a full browser engine that receives security fixes every few weeks. Browser engines are a favourite target for exploits, so an outdated WebView puts every app that uses it at risk.

**What to do:** Update Android System WebView, or the browser that provides it (Chrome, Vanadium…), from your app store, and install pending system updates.

### INTG-1080 Time since restart

Notice · Base tier · Android 8.0 and later · fails when the phone hasn't restarted for more than 7 days

After a restart, Android keeps the keys to your files out of memory until you first unlock the phone: the state phone-cracking tools find hardest. From then on the keys stay in memory, even while the screen is locked, until the next restart. A restart also removes spyware that lives only in memory, as many zero-click exploits do, and finishes updates that wait for one. The NSA's mobile device guidance advises restarting once a week.

**What to do:** Restart the phone: hold the power button (with volume up on some phones) and tap Restart. Once a week is enough. GrapheneOS can also restart by itself after the phone stays locked for a while (Auto reboot).

### INTG-1090 Storage space

Notice · Base tier · Android 8.0 and later · fails when more than 80% of the internal storage is in use

System updates are downloaded and unpacked on the phone before they install, and need free space for that. On a nearly full phone, security updates, app updates and WebView updates fail or wait until space is freed, so known flaws stay open for longer.

**What to do:** Open Settings › Storage and free up space: uninstall apps you don't use, delete downloads you no longer need, and move photos and videos to a computer or your own server. Then install pending system updates.

### INTG-1201 SELinux mode

Critical · Shizuku tier · Android 8.0 and later · fails when SELinux is permissive or disabled

SELinux confines every app and system service to what its policy allows, so a bug in one of them can't take over the whole phone. Production Android always enforces it; a permissive or disabled SELinux usually means a modified kernel or ROM. Apps can't read the mode, but the shell user Shizuku runs as can.

**What to do:** Settings can't turn SELinux back on. Install firmware that keeps it enforcing, such as the manufacturer's stock firmware or a ROM whose kernel enforces SELinux.

### INTG-1202 Spoofed boot properties

Warning · Shizuku tier · Android 8.0 and later · fails when a security-relevant ro.boot.* property differs from the kernel command line (a props spoofer)

Android copies the bootloader's state into ro.boot.* properties at boot: whether the bootloader is unlocked, whether verified boot passed, and on Samsung whether the Knox warranty fuse is blown. Modules that hide root rewrite these to look clean, which lets other apps trust a phone whose bootloader is actually open. The kernel command line keeps the real values, and only a shell can read it.

**What to do:** A mismatch means a module is faking the bootloader state. Decide whether you want that: it is how some apps are made to trust a rooted phone. To see the true state, remove the props-spoofing module (often a Play Integrity or "MagiskHide props" module) and scan again; the real values are what the kernel command line shows here.

### INTG-1301 Root modules

Info · Root tier · Android 8.0 and later · fails when an enabled root module is installed (information only)

Magisk, KernelSU and APatch modules change the system at every boot, with full root rights and before any app or security setting can stop them. Each one is code you trust completely. This check lists them for your review and doesn't count in the score.

**What to do:** Open your root manager's Modules screen and remove modules you no longer use or don't fully trust. Install modules only from their authors' own pages.

### INTG-1302 Root boot code others can change

Notice · Root tier · Android 8.0 and later · fails when a boot script root runs, or a folder holding it, is not owned by root or is writable by others

Your root manager runs the scripts in /data/adb/service.d and post-fs-data.d, and each module's own boot scripts, as root every time the phone starts. If one of those files, or a folder on the way to it, can be written by a user other than root, that user can swap in their own code and it runs with full root rights at the next boot.

**What to do:** Make every boot script and its folders owned by root and writable by root alone: for a file, `chown root:root <file>` and `chmod 700 <file>`; check that /data/adb and its subfolders are 700 root too. A module's scripts are fixed by removing or reinstalling the module from a source you trust.

### INTG-1303 Programs staged in shared temp

Notice · Root tier · Android 8.0 and later · fails when a script or executable is staged in /data/local/tmp

/data/local/tmp is where a computer with adb, or an app using Shizuku, drops files, since it is the one place they can write without root. Scripts or executables sitting there are often left over from setup or testing. They matter most if you ever run them as root: the folder is owned by the shell user, so adb or a Shizuku app can replace a file there before root runs it.

**What to do:** Remove what you no longer need from /data/local/tmp. For anything you do run as root, move it somewhere only root can write (for example /data/adb) and set it to `chown root:root` and `chmod 700` first, so the shell user can't change it under you.

## Access control

| ID | Check | Severity | Fails when |
|---|---|---|---|
| **[Base](#base-tier)** | | | |
| [ACCS-2001](#accs-2001-secure-lock-screen) | Secure lock screen | Critical | no PIN, pattern or password is set |
| [ACCS-2002](#accs-2002-screen-timeout) | Screen timeout | Notice | the screen stays on for more than 2 minutes |
| [ACCS-2003](#accs-2003-password-visibility) | Password visibility | Notice | typed password characters are shown |
| [ACCS-2004](#accs-2004-lock-screen-notifications) | Lock screen notifications | Notice | notification content is visible while the phone is locked |
| [ACCS-2005](#accs-2005-stay-awake-while-charging) | Stay awake while charging | Notice | the screen never turns off, so never locks, while charging |
| [ACCS-2006](#accs-2006-lock-after-screen-timeout) | Lock after screen timeout | Notice | the phone stays unlocked for more than 30 seconds after the screen turns off |
| [ACCS-2007](#accs-2007-screen-lock-strength) | Screen lock strength (Android 10+) | Notice | the screen lock is a pattern or a PIN with repeated or ordered digits |
| [ACCS-2008](#accs-2008-notification-history) | Notification history (Android 11+) | Notice | notification history is on, keeping 24 hours of notification text |
| [ACCS-2009](#accs-2009-biometric-unlock-strength) | Biometric unlock strength (Android 11+) | Notice | the only biometric unlock set up is weak (Class 2), such as most camera-only face unlock |
| [ACCS-2010](#accs-2010-developer-options) | Developer options | Notice | developer options are on |
| [ACCS-2011](#accs-2011-usb-debugging) | USB debugging | Warning | adb over USB is on |
| [ACCS-2012](#accs-2012-wireless-debugging) | Wireless debugging (Android 11+) | Warning | adb over Wi-Fi is on |
| [ACCS-2013](#accs-2013-usb-debugging-authorization-timeout) | USB debugging authorization timeout (Android 11+) | Notice | computers allowed for USB debugging keep their access for more than 7 days without connecting, or for good |
| [ACCS-2020](#accs-2020-remote-lock-and-erase) | Remote lock and erase | Notice | no app or known service can lock and erase the phone remotely |
| **[ADB](#adb-tier)** | | | |
| [ACCS-2101](#accs-2101-smart-lock-and-extend-unlock) | Smart Lock and Extend Unlock | Notice | a trust agent such as Smart Lock can keep the phone unlocked |
| **[Shizuku](#shizuku-tier)** | | | |
| [ACCS-2201](#accs-2201-sim-card-pin) | SIM card PIN (Android 11+) | Notice | a SIM in use has its PIN turned off |
| [ACCS-2202](#accs-2202-device-controls-on-the-lock-screen) | Device controls on the lock screen (Android 13+) | Notice | device controls can be used without unlocking the phone |
| **[Root](#root-tier)** | | | |
| [ACCS-2301](#accs-2301-computers-trusted-for-usb-debugging) | Computers trusted for USB debugging | Notice | a computer is trusted for USB debugging |

### ACCS-2001 Secure lock screen

Critical · Base tier · Android 8.0 and later · fails when no PIN, pattern or password is set

Without a PIN, pattern or password, anyone holding the device can use it, and the encryption of your data is not tied to any secret you know. Biometrics and apps that protect their keys with your screen lock depend on it too.

**What to do:** Set a PIN or password. A PIN of 6 or more digits or an alphanumeric password is much stronger than a pattern.

### ACCS-2002 Screen timeout

Notice · Base tier · Android 8.0 and later · fails when the screen stays on for more than 2 minutes

The phone locks itself only after the screen turns off. A long timeout leaves an unlocked phone open to anyone nearby, for example on a desk or table.

**What to do:** Set Screen timeout to 1 minute or less (Settings › Display).

### ACCS-2003 Password visibility

Notice · Base tier · Android 8.0 and later · fails when typed password characters are shown

With "Show passwords" on, each character you type into a password field stays visible for a moment. Someone looking over your shoulder, a screen recording or a malicious accessibility service can pick it up.

**What to do:** Turn off "Show passwords" (Settings › Privacy on most phones, Settings › Security on older ones).

### ACCS-2004 Lock screen notifications

Notice · Base tier · Android 8.0 and later · fails when notification content is visible while the phone is locked

Notifications on the lock screen can be read without unlocking the phone. Message previews and one-time login codes sent by SMS are then visible to anyone who picks it up.

**What to do:** In the notification settings, set notifications on the lock screen to hide sensitive content, or not to show at all.

### ACCS-2005 Stay awake while charging

Notice · Base tier · Android 8.0 and later · fails when the screen never turns off, so never locks, while charging

With "Stay awake" on, the screen never turns off while the phone charges, so it never locks either. Anyone who picks up a charging phone that was left unlocked gets in without the PIN.

**What to do:** Turn off "Stay awake" in Developer options.

### ACCS-2006 Lock after screen timeout

Notice · Base tier · Android 8.0 and later · fails when the phone stays unlocked for more than 30 seconds after the screen turns off

When the screen turns off by itself, Android waits this long before it asks for your PIN again. Anyone who picks the phone up in that window gets in without it, which is how many phone thefts work. The power button can lock at once, but apps can't read that setting.

**What to do:** Under Settings › Security › Screen lock (gear icon), set Lock after screen timeout to 30 seconds or less, and turn on "Power button instantly locks".

### ACCS-2007 Screen lock strength

Notice · Base tier · Android 10 and later · fails when the screen lock is a pattern or a PIN with repeated or ordered digits

A pattern can be read from smudges on the screen or by watching over your shoulder, and a PIN such as 1234 or 1111 is among the first anyone tries. Android rates the screen lock low, medium or high without revealing it: low means a pattern, or a PIN with repeated or ordered digits.

**What to do:** Change the screen lock to a PIN of 6 or more digits without repeated or ordered digits, or to a password (Settings › Security › Screen lock).

### ACCS-2008 Notification history

Notice · Base tier · Android 11 and later · fails when notification history is on, keeping 24 hours of notification text

With notification history on, Android saves the text of every notification from the last 24 hours, message previews and one-time login codes included. The copy stays after you dismiss the notification and after the app deletes the message or makes it disappear. Anyone who gets into the unlocked phone can scroll through it, and forensic tools can extract it.

**What to do:** Turn off notification history (Settings › Notifications › Notification history); Android then deletes what it saved. In messaging apps, also hide message content in notifications, for example in Signal under Settings › Notifications › Show.

### ACCS-2009 Biometric unlock strength

Notice · Base tier · Android 11 and later · fails when the only biometric unlock set up is weak (Class 2), such as most camera-only face unlock

Android rates fingerprint and face unlock by how hard they are to fool. A weak (Class 2) one, typically face unlock that uses only the front camera, can be fooled more easily, by a photo or a look-alike, yet it still unlocks the phone. Strong (Class 3) sensors are much harder to fool. Some phones also have a convenience (Class 1) face unlock, weaker still, which Android hides from apps, as it does face unlock some makers build on their own.

**What to do:** In Settings › Security (Device unlock or Biometrics on some phones), remove the weak face unlock or turn off its use for unlocking the phone, and keep a fingerprint or your PIN or password instead. If the phone has a face unlock Droynis can't see, check it there too.

### ACCS-2010 Developer options

Notice · Base tier · Android 8.0 and later · fails when developer options are on

Developer options unlock debugging features such as USB and wireless debugging, mock locations and OEM unlocking. They are not meant for everyday use, and keeping them hidden lowers the chance of a risky switch being left on.

**What to do:** Turn Developer options off with the switch at the top of the Developer options screen. Permissions granted to Droynis with adb stay granted.

### ACCS-2011 USB debugging

Warning · Base tier · Android 8.0 and later · fails when adb over USB is on

With USB debugging on, any computer you have authorized can install apps, grant them permissions, read shared storage and capture the screen through adb. It widens what someone with physical access, or with control of a computer you once trusted, can do.

**What to do:** Turn off USB debugging in Developer options and tap "Revoke USB debugging authorizations". Permissions granted to Droynis with adb stay granted afterwards.

### ACCS-2012 Wireless debugging

Warning · Base tier · Android 11 and later · fails when adb over Wi-Fi is on

Wireless debugging exposes adb on the Wi-Fi network. Any computer you have paired can then install apps and control the phone over the network, without a cable.

**What to do:** Turn off Wireless debugging in Developer options and remove paired devices you no longer use. Android also turns it off when you leave the Wi-Fi network.

### ACCS-2013 USB debugging authorization timeout

Notice · Base tier · Android 11 and later · fails when computers allowed for USB debugging keep their access for more than 7 days without connecting, or for good

A computer you allowed for USB or wireless debugging gets full adb access whenever debugging is on: it can install apps and read app data. Since Android 11 the phone forgets a computer that hasn't connected for 7 days. The developer option "Disable adb authorization timeout" stops that, so every computer you ever allowed stays trusted for good.

**What to do:** Open Settings › System › Developer options and turn off "Disable adb authorization timeout". "Revoke USB debugging authorizations" on the same screen forgets every computer at once.

### ACCS-2020 Remote lock and erase

Notice · Base tier · Android 8.0 and later · fails when no app or known service can lock and erase the phone remotely

If the phone is lost or stolen, a find-my-device service lets you locate, lock and erase it from another device. Android doesn't let apps see whether Google's or the phone maker's service is turned on, so Droynis looks for an app allowed to lock and erase the phone, and for the built-in services it knows.

**What to do:** Turn on your phone's find-my-device service: with Google services, Settings › Google › All services › Find Hub, and Theft protection next to it; on Samsung, Find My Mobile. Without Google services, the open-source FMD app (on F-Droid) can locate, lock and erase the phone. Once you have seen it turned on, you can mute this check.

### ACCS-2101 Smart Lock and Extend Unlock

Notice · ADB tier · Android 8.0 and later · fails when a trust agent such as Smart Lock can keep the phone unlocked

Smart Lock (Extend Unlock on newer phones) keeps the phone unlocked near a trusted device or place, or while you carry it. Whoever takes it from your pocket, or picks it up next to your car's Bluetooth, gets an unlocked phone. Android keeps this in its trust service, which only the ADB, Shizuku or root tier can read.

**What to do:** Open Settings › Security › Smart Lock or Extend Unlock (the location varies by vendor) and remove trusted devices, trusted places and on-body detection you don't need.

### ACCS-2201 SIM card PIN

Notice · Shizuku tier · Android 11 and later · fails when a SIM in use has its PIN turned off

Without a SIM PIN, whoever takes the SIM out of a lost or stolen phone can put it in another phone and receive your calls and texts, including the one-time codes that reset bank and email passwords. With the PIN on, the SIM stays locked after every restart until the PIN is entered. Most operators ship SIMs with a PIN, but it is easy to turn off.

**What to do:** Turn on the SIM card lock (Settings › Security › SIM card lock, or Security & privacy › More security settings; the place varies by vendor) and change the PIN from the one printed on the SIM's card. Keep the PUK code somewhere safe: three wrong PINs lock the SIM until it is entered.

### ACCS-2202 Device controls on the lock screen

Notice · Shizuku tier · Android 13 and later · fails when device controls can be used without unlocking the phone

Device controls switch smart home devices, such as lights, plugs, heating or a lock, from the phone. With "Show device controls" and "Use device controls" ("Control from locked device" on Android 13) both on, anyone holding your locked phone can use each control whose app doesn't ask for the unlock; the app decides which ones do. Android hides these switches from apps; the shell user Shizuku runs as can read them.

**What to do:** Open Settings › Display › Lock screen and turn off "Use device controls" ("Control from locked device" on Android 13), or "Show device controls".

### ACCS-2301 Computers trusted for USB debugging

Notice · Root tier · Android 8.0 and later · fails when a computer is trusted for USB debugging

Every computer you once allowed for USB debugging keeps its key on the phone, and gets adb again without asking whenever debugging is on, even after you turn it off and back on. Android 11 and later forget a computer after 7 days without a connection, unless that timeout is turned off. Only root can read the list.

**What to do:** In Developer options tap "Revoke USB debugging authorizations". Your own computer asks again the next time you connect it. If Developer options are off, turn them on first: in About phone, tap Build number seven times.

## Apps and permissions

| ID | Check | Severity | Fails when |
|---|---|---|---|
| **[Base](#base-tier)** | | | |
| [APPS-4001](#apps-4001-accessibility-services) | Accessibility services | Notice | any accessibility service is enabled (a warning when its app came from outside an app store) |
| [APPS-4002](#apps-4002-device-admin-apps) | Device admin apps | Notice | a device admin you installed, or a device or profile owner, is active (a warning when it came from outside an app store) |
| [APPS-4003](#apps-4003-debuggable-apps) | Debuggable apps | Warning | an installed app is debuggable |
| [APPS-4004](#apps-4004-apps-from-unknown-sources) | Apps from unknown sources | Notice | an app came from outside a known app store |
| [APPS-4005](#apps-4005-notification-access) | Notification access | Notice | an app you installed can read all notifications (a warning when it came from outside an app store) |
| [APPS-4006](#apps-4006-keyboard-apps) | Keyboard apps | Notice | a third-party keyboard is enabled |
| [APPS-4007](#apps-4007-apps-built-for-old-android) | Apps built for old Android | Notice | a user app targets Android 8.1 (API 27) or older |
| [APPS-4008](#apps-4008-apps-that-can-read-your-sms-or-call-log) | Apps that can read your SMS or call log | Notice | an app other than your SMS and phone apps, or one of those installed from outside an app store, can read SMS or the call log (a warning when it came from outside an app store) |
| [APPS-4009](#apps-4009-apps-that-can-send-sms) | Apps that can send SMS | Notice | an app other than your SMS app can send SMS (a warning when it came from outside an app store) |
| [APPS-4010](#apps-4010-autofill-service) | Autofill service (Android 9+) | Notice | an autofill service from an app you installed is selected (a warning when it came from outside an app store) |
| [APPS-4011](#apps-4011-digital-assistant-app) | Digital assistant app | Notice | the digital assistant is an app you installed (a warning when it came from outside an app store) |
| [APPS-4012](#apps-4012-apps-with-location-all-the-time) | Apps with location all the time (Android 10+) | Notice | an app you installed may use location all the time (a warning when it came from outside an app store) |
| [APPS-4013](#apps-4013-apps-that-skip-battery-optimization) | Apps that skip battery optimization | Info | an app you installed may skip battery optimization (information only) |
| [APPS-4014](#apps-4014-google-play-services) | Google Play services | Info | Google Play services is built into the system, with privileged access (information only) |
| [APPS-4015](#apps-4015-app-scanning-play-protect) | App scanning (Play Protect) | Warning | the install-time app verifier (Play Protect) is turned off |
| [APPS-4016](#apps-4016-apps-with-shizuku-access) | Apps with Shizuku access | Notice | an app other than Droynis may use Shizuku (a warning when it came from outside an app store) |
| **[ADB](#adb-tier)** | | | |
| [APPS-4102](#apps-4102-apps-that-can-draw-over-other-apps) | Apps that can draw over other apps (Android 10+) | Notice | a user app may display over other apps |
| [APPS-4103](#apps-4103-apps-with-access-to-all-files) | Apps with access to all files (Android 11+) | Notice | a user app has all files access |
| [APPS-4104](#apps-4104-apps-that-can-install-other-apps) | Apps that can install other apps (Android 10+) | Notice | a user app other than a known app store may install apps |
| [APPS-4105](#apps-4105-apps-with-usage-access) | Apps with usage access (Android 10+) | Notice | a user app has usage access |
| [APPS-4106](#apps-4106-apps-that-can-change-system-settings) | Apps that can change system settings (Android 10+) | Info | a user app may change system settings (information only) |
| [APPS-4107](#apps-4107-apps-that-can-manage-your-media) | Apps that can manage your media (Android 12+) | Info | a user app may change or delete media without asking (information only) |
| **[Shizuku](#shizuku-tier)** | | | |
| [APPS-4201](#apps-4201-passkey-and-password-providers) | Passkey and password providers (Android 14+) | Notice | a passkey or password provider from an app you installed is turned on (a warning when it came from outside an app store) |
| [APPS-4202](#apps-4202-clipboard-access-alerts) | Clipboard access alerts (Android 12+) | Notice | "Show clipboard access" is off, so apps read the clipboard silently |
| **[Root](#root-tier)** | | | |
| [APPS-4301](#apps-4301-apps-with-root-access) | Apps with root access | Warning | an app other than Droynis may get root |
| [APPS-4302](#apps-4302-root-access-over-adb) | Root access over ADB | Warning | Magisk grants root to the ADB shell (Superuser access includes ADB; the default) |

### APPS-4001 Accessibility services

Notice · Base tier · Android 8.0 and later · fails when any accessibility service is enabled (a warning when its app came from outside an app store)

An accessibility service can read everything on screen and tap on your behalf. Screen readers and password managers need this, but it is also the favorite tool of Android banking trojans, which arrive as apps installed from outside an app store: such an app with this access is a warning.

**What to do:** Keep only services you recognize and still use; turn the others off under Settings › Accessibility.

### APPS-4002 Device admin apps

Notice · Base tier · Android 8.0 and later · fails when a device admin you installed, or a device or profile owner, is active (a warning when it came from outside an app store)

Device admin apps can lock or wipe the phone and enforce password rules; a device or profile owner can manage it completely. Find-my-device and work profiles use this legitimately; anything you do not recognize deserves a closer look, and one installed from outside an app store is a warning. Admins that came with the phone are listed but don't count, unless they own the device.

**What to do:** Review them under Settings › Security › Device admin apps (the location varies by vendor) and deactivate the ones you do not need.

### APPS-4003 Debuggable apps

Warning · Base tier · Android 8.0 and later · fails when an installed app is debuggable

A debuggable app lets anyone with adb access read its private data and run code inside it. Store builds are never debuggable, so a debuggable app is a development build or has been modified.

**What to do:** Uninstall debuggable apps you are not developing yourself, or replace them with the official release. Droynis itself is excluded from this check.

### APPS-4004 Apps from unknown sources

Notice · Base tier · Android 8.0 and later · fails when an app came from outside a known app store

Apps installed from a downloaded file or over adb skip the review an app store performs and usually do not update automatically. That is fine for apps you trust, but each one is worth knowing about.

**What to do:** Review the list and uninstall apps you do not recognize. Prefer a store such as F-Droid, Accrescent or Google Play, which also keeps the apps updated.

### APPS-4005 Notification access

Notice · Base tier · Android 8.0 and later · fails when an app you installed can read all notifications (a warning when it came from outside an app store)

An app with notification access reads every notification as it arrives, including message previews and one-time login codes sent by SMS, and can act on them. Watch and automation apps need it; any other app that has it deserves a second look, and one installed from outside an app store is a warning. Apps that came with the phone, like the launcher's badges, are listed but don't count.

**What to do:** Under Special app access › Notification access (the name varies by vendor), turn it off for apps that do not need it.

### APPS-4006 Keyboard apps

Notice · Base tier · Android 8.0 and later · fails when a third-party keyboard is enabled

A keyboard sees everything you type, passwords and private messages included, and some send it to the cloud for suggestions. Keyboards built into the system come with the phone's trust; any other one should come from a developer you trust.

**What to do:** Disable keyboards you do not use under Settings › System › Keyboard (the path varies). An open-source keyboard that works offline keeps your typing on the phone.

### APPS-4007 Apps built for old Android

Notice · Base tier · Android 8.0 and later · fails when a user app targets Android 8.1 (API 27) or older

Android applies many protections only to apps that declare a recent target version, for example scoped storage and limits on reading device identifiers. Apps built for Android 8.1 or older skip them and are usually no longer maintained; Android 14 even refuses to install apps built for Android 5.1 or older.

**What to do:** Update these apps, or replace the ones that are no longer maintained.

### APPS-4008 Apps that can read your SMS or call log

Notice · Base tier · Android 8.0 and later · fails when an app other than your SMS and phone apps, or one of those installed from outside an app store, can read SMS or the call log (a warning when it came from outside an app store)

One-time login codes arrive by SMS, so an app that reads SMS can take over accounts protected by them; SMS-stealing apps are among the most common Android malware. The call log shows who you talk to. Your SMS and phone apps need these permissions and apps that came with the phone are listed but don't count; any other app deserves a look, and one installed from outside an app store is a warning, your SMS or phone app included.

**What to do:** Open Settings › Privacy › Permission manager › SMS and Call logs (or Settings › Apps › the app › Permissions) and set them to "Don't allow" for apps that don't need them. Uninstall apps you don't recognize.

### APPS-4009 Apps that can send SMS

Notice · Base tier · Android 8.0 and later · fails when an app other than your SMS app can send SMS (a warning when it came from outside an app store)

An app that can send SMS can text premium-rate numbers that are charged to your phone bill, or send messages in your name, without opening your messaging app; billing-fraud malware such as Joker does exactly that. Android asks before an app texts a premium number, unless its Premium SMS access is set to Always allow. Your SMS app needs this permission and apps that came with the phone are listed but don't count; any other app deserves a look, and one installed from outside an app store is a warning.

**What to do:** Open Settings › Privacy › Permission manager › SMS (or Settings › Apps › the app › Permissions) and set it to "Don't allow" for apps that don't need it. Under Settings › Apps › Special app access › Premium SMS access, keep every app on Ask or Never allow. Uninstall apps you don't recognize.

### APPS-4010 Autofill service

Notice · Base tier · Android 9 and later · fails when an autofill service from an app you installed is selected (a warning when it came from outside an app store)

The autofill service fills in passwords, addresses and card numbers for you, so it sees the forms you fill in, in every app. Password managers use it; a malicious one reads what you type into login forms. Autofill that came with the phone is part of the system; any other one should come from a developer you trust, and one installed from outside an app store is a warning.

**What to do:** Open Settings › Passwords, passkeys & accounts (on Android 11 and older Settings › System › Languages & input › Advanced › Autofill service) and pick a password manager you trust, or None.

### APPS-4011 Digital assistant app

Notice · Base tier · Android 8.0 and later · fails when the digital assistant is an app you installed (a warning when it came from outside an app store)

The digital assistant opens when you long-press the power or home button or say its wake word. When you call it, it can read what is on the screen and take a screenshot ("Use text from screen", on unless you turn it off), and a voice assistant can listen for its wake word. One that came with the phone is part of the system; any other one should come from a developer you trust, and one installed from outside an app store is a warning.

**What to do:** Open Settings › Apps › Default apps › Digital assistant app. Choose None if you don't use an assistant, or turn off "Use text from screen" and "Use screenshot".

### APPS-4012 Apps with location all the time

Notice · Base tier · Android 10 and later · fails when an app you installed may use location all the time (a warning when it came from outside an app store)

An app allowed location "All the time" can see where you are while you aren't using it, and build a history of the places you go. Navigation, fitness and find-my-phone apps may need it; most apps work with "Only while using the app". Apps that came with the phone are listed but don't count; one installed from outside an app store is a warning, as stalkerware asks for exactly this.

**What to do:** Open Settings › Location › App location permissions (on some phones Settings › Privacy › Permission manager › Location) and set the apps listed to "Allow only while using the app" or "Don't allow".

### APPS-4013 Apps that skip battery optimization

Info · Base tier · Android 8.0 and later · fails when an app you installed may skip battery optimization (information only)

An app set to "Unrestricted" battery use ("Not optimized" on older Android) is exempt from Doze and App Standby, so it can wake the phone and keep running in the background at any time. Messengers, sync and automation apps use this to work on time; stalkerware and remote-access tools ask for it to keep running unnoticed. Apps that came with the phone aren't listed. This check is for your information and doesn't count in the score.

**What to do:** Open Settings › Apps › the app › App battery usage (Battery on some phones) and choose "Optimized" for apps that don't need to run in the background. Uninstall apps you don't recognize.

### APPS-4014 Google Play services

Info · Base tier · Android 8.0 and later · fails when Google Play services is built into the system, with privileged access (information only)

Google Play services is the layer behind Google sign-in, push notifications, location services and the advertising ID, and it shares device data with Google. Built into the system, as on most phones, it holds privileged access that no ordinary app can have and that you can't take back. Installed as an ordinary app, as GrapheneOS's sandboxed Google Play is, it gets only the permissions you grant; microG is an open-source replacement that shares far less.

**What to do:** Information only: on most phones it can't be removed without replacing the operating system. To limit it, turn off the Google features you don't use (Settings › Google), delete the advertising ID (Settings › Privacy › Ads) and review its permissions in App info. GrapheneOS, or a microG-based system such as /e/OS or LineageOS for microG, runs without it in the system.

### APPS-4015 App scanning (Play Protect)

Warning · Base tier · Android 8.0 and later · fails when the install-time app verifier (Play Protect) is turned off

Before an app is installed, Android asks the package verifier (Play Protect on phones with Google services, an OEM scanner on others) to check it against known malware. With the verifier off, apps from any source install unchecked, so a sideloaded or repackaged app carrying malware is not flagged.

**What to do:** Turn scanning back on in Play Protect (Play Store › your profile › Play Protect › Settings › Scan apps with Play Protect), or under Settings › Security. The verifier only scans; it still lets you install an app it warns about.

### APPS-4016 Apps with Shizuku access

Notice · Base tier · Android 8.0 and later · fails when an app other than Droynis may use Shizuku (a warning when it came from outside an app store)

Shizuku gives the apps you allow the rights of adb, or of root when Shizuku runs with root. Such an app can install apps and grant them permissions, read the system log, change hidden settings, take screenshots and tap the screen for you, without asking again. Allow only apps you trust; one installed from outside an app store is a warning. Sui, the variant for rooted phones, keeps its own list, which Droynis can't read.

**What to do:** Open Shizuku, tap Application management ("Authorized … applications") and turn off the apps you no longer use or don't fully trust. Settings › Apps › the app › Permissions › Shizuku › Don't allow does the same.

### APPS-4102 Apps that can draw over other apps

Notice · ADB tier · Android 10 and later · fails when a user app may display over other apps

Apps allowed to "Display over other apps" (on Samsung: "Appear on top") can put windows on top of anything on the screen. Chat bubbles and screen filters use this; malware uses it to cover real apps with fake login forms or to trick you into tapping something else. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Display over other apps and turn it off for every app listed that doesn't need it. Uninstall apps you don't recognize.

### APPS-4103 Apps with access to all files

Notice · ADB tier · Android 11 and later · fails when a user app has all files access

"All files access" lets an app read, change and delete every file in shared storage: photos, downloads and documents, whatever app made them. File managers and backup apps need it; most other apps don't. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › All files access and turn it off for every app listed that doesn't manage or back up your files.

### APPS-4104 Apps that can install other apps

Notice · ADB tier · Android 10 and later · fails when a user app other than a known app store may install apps

Apps allowed to "Install unknown apps" can offer you APK files to install. You still confirm each one, but a malicious or hacked app with this right can push malware at you. App stores need it and don't count. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Install unknown apps and turn it off for the apps listed. Turn it on again only while you install something you trust.

### APPS-4105 Apps with usage access

Notice · ADB tier · Android 10 and later · fails when a user app has usage access

"Usage access" (on Samsung: "Usage data access") shows an app which other apps you use, when and for how long. Launchers and digital wellbeing apps use it; so does stalkerware, to follow what you do on the phone. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Usage access and turn it off for every app listed that doesn't need it.

### APPS-4106 Apps that can change system settings

Info · ADB tier · Android 10 and later · fails when a user app may change system settings (information only)

"Modify system settings" (on Samsung: "Change system settings") lets an app change everyday settings such as brightness, ringtone and screen timeout. It can't reach security settings, so this check is for your information and doesn't count in the score. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Modify system settings and turn it off for apps you don't expect there.

### APPS-4107 Apps that can manage your media

Info · ADB tier · Android 12 and later · fails when a user app may change or delete media without asking (information only)

"Media management" (on Samsung: "Manage media") lets an app that can see your photos, videos and audio also change, move or delete them without asking you each time. Gallery apps use it. This check is for your information and doesn't count in the score. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › Special app access › Media management apps and turn it off for apps that don't organize your media.

### APPS-4201 Passkey and password providers

Notice · Shizuku tier · Android 14 and later · fails when a passkey or password provider from an app you installed is turned on (a warning when it came from outside an app store)

Since Android 14, password managers can serve passkeys and passwords to every app through Android's Credential Manager. A provider you turn on keeps what you save with it, and is asked each time an app or website wants you to sign in, so it also learns where you have accounts. Providers that came with the phone are listed but don't count; any other one should come from a developer you trust, and one installed from outside an app store is a warning. Android hides this list from apps; the shell user Shizuku runs as can read it.

**What to do:** Open Settings › Passwords, passkeys & accounts and turn off the providers you don't use, under Preferred service and Additional services.

### APPS-4202 Clipboard access alerts

Notice · Shizuku tier · Android 12 and later · fails when "Show clipboard access" is off, so apps read the clipboard silently

What you copy often holds passwords, one-time codes, addresses or crypto wallet addresses. Since Android 12 a short message tells you when an app reads it, so an app that reads the clipboard without you pasting shows itself. Turning "Show clipboard access" off hides that. Android hides this switch from apps; the shell user Shizuku runs as can read it.

**What to do:** Open Settings › Privacy (Settings › Security & privacy › Privacy controls on newer phones) and turn on "Show clipboard access"; searching Settings for "clipboard" finds it too.

### APPS-4301 Apps with root access

Warning · Root tier · Android 8.0 and later · fails when an app other than Droynis may get root

An app with root can read every other app's data, change the system and hide what it does: Android's app sandbox no longer limits it. Grant root only to apps you trust completely, and take it back from apps you no longer use. Droynis reads Magisk's list; KernelSU and APatch keep theirs in formats it can't read yet.

**What to do:** Open your root manager's Superuser screen and revoke root from apps you don't use or don't fully trust. Revoking adb shell's root means a computer with adb gets no root.

### APPS-4302 Root access over ADB

Warning · Root tier · Android 8.0 and later · fails when Magisk grants root to the ADB shell (Superuser access includes ADB; the default)

Magisk can hand root to apps, to the ADB shell, to both or to neither. The default is both, so any computer you have trusted for USB debugging can run `adb shell su` and get a full root shell, and so can malware on that computer. Limiting root to apps keeps adb, and anything reaching the phone over it, out of root.

**What to do:** In the Magisk app, open Settings › Superuser access and set it to "Apps only". Keep USB debugging off when you don't need it, and review the computers trusted for it (ACCS-2301).

## Suspicious apps

| ID | Check | Severity | Fails when |
|---|---|---|---|
| **[Base](#base-tier)** | | | |
| [SUSP-5001](#susp-5001-apps-hiding-from-the-app-drawer) | Apps hiding from the app drawer | Warning | an installed app turned its app drawer icon off, or shows a blank name or a transparent icon (critical when it came from outside an app store, or has accessibility, device admin or notification access) |
| [SUSP-5002](#susp-5002-hidden-apps-set-up-to-run-in-the-background) | Hidden apps set up to run in the background | Warning | an app that hides from the app drawer, or one without an icon from outside an app store, declares it starts at boot, runs foreground services, draws over other apps, shows full-screen pop-ups or skips battery limits (critical when it hides and came from outside an app store) |
| [SUSP-5003](#susp-5003-hidden-apps-showing-screens) | Hidden apps showing screens | Warning | an app that hides from the app drawer, or one without an icon from outside an app store, brought its own screen to the front in the last 7 days (critical when it hides and came from outside an app store) |
| [SUSP-5004](#susp-5004-apps-installed-by-another-app) | Apps installed by another app | Warning | an app was installed by another app you installed that isn't an app store or an installer tool |
| [SUSP-5005](#susp-5005-apps-with-banking-trojan-permissions) | Apps with banking-trojan permissions | Warning | an installed app declares an accessibility service and asks for SMS and to draw over other apps (critical when it came from outside an app store or its accessibility service is on) |
| [SUSP-5006](#susp-5006-apps-signed-with-a-debug-or-test-key) | Apps signed with a debug or test key | Notice | a user app is signed with Android's debug key or a public test key (warning for a test key, or a debug key on an app that isn't debuggable) |
| [SUSP-5007](#susp-5007-known-stalkerware-and-monitoring-apps) | Known stalkerware and monitoring apps | Warning | an app you installed has the package name or signing key of an app on Echap's Stalkerware Indicators list (critical for stalkerware, warning for a monitoring app that doesn't hide) |
| **[ADB](#adb-tier)** | | | |
| [SUSP-5101](#susp-5101-hidden-apps-running-in-the-background) | Hidden apps running in the background (Android 10+) | Warning | an app that hides from the app drawer, or one without an icon from outside an app store, runs a service it started, or started a foreground service or drew over other apps in the last 7 days (critical when it hides and came from outside an app store) |
| [SUSP-5102](#susp-5102-background-camera-microphone-and-location-use) | Background camera, microphone and location use (Android 10+) | Notice | a user app used the camera, microphone or location from the background in the last 7 days (warning for camera or microphone) |
| [SUSP-5103](#susp-5103-apps-that-can-record-the-screen-without-asking) | Apps that can record the screen without asking (Android 10+) | Warning | a user app may record or cast the screen without asking |
| [SUSP-5104](#susp-5104-background-sms-call-log-and-contacts-use) | Background SMS, call log and contacts use (Android 10+) | Notice | a user app read SMS, the call log or contacts, or received SMS, from the background in the last 7 days (warning when it came from outside an app store) |

### SUSP-5001 Apps hiding from the app drawer

Warning · Base tier · Android 8.0 and later · fails when an installed app turned its app drawer icon off, or shows a blank name or a transparent icon (critical when it came from outside an app store, or has accessibility, device admin or notification access)

Adware and stalkerware hide after their first start, so you can't find them to remove them: they turn their app drawer icon off, or keep it but give it a blank name and a transparent icon. Since Android 10 an app that turns its icon off usually still gets a placeholder that opens App info, which is why hiding apps now use the blank name and transparent icon. A hiding app with accessibility, device admin or notification access is how stalkerware and banking trojans are set up. A few legitimate apps hide too, such as anti-theft apps, so check whether you installed each one on purpose.

**What to do:** Open each app listed (the button next to it opens its App info) and uninstall it unless you know why it hides. If Uninstall is greyed out, the app is a device admin: remove it under Security › Device admin apps first. An app with a blank name is listed here by its package name.

### SUSP-5002 Hidden apps set up to run in the background

Warning · Base tier · Android 8.0 and later · fails when an app that hides from the app drawer, or one without an icon from outside an app store, declares it starts at boot, runs foreground services, draws over other apps, shows full-screen pop-ups or skips battery limits (critical when it hides and came from outside an app store)

An app you can't open from the app drawer has little reason to start by itself, yet adware does: it starts with the phone, keeps a service running and pops up over other apps. Droynis lists apps without a visible app drawer icon that declare one of these: starting when the phone starts, foreground services, drawing over other apps, full-screen pop-ups, or skipping battery limits. Add-ons such as plugins often have no icon of their own; from an app store they are listed, not counted.

**What to do:** Uninstall apps listed here that you don't recognize. For an add-on you use, check that the app it belongs to is one you trust.

### SUSP-5003 Hidden apps showing screens

Warning · Base tier · Android 8.0 and later · fails when an app that hides from the app drawer, or one without an icon from outside an app store, brought its own screen to the front in the last 7 days (critical when it hides and came from outside an app store)

An app without a visible app drawer icon has no screen you open yourself, so when it shows one anyway, it usually opened it by itself: that is how adware shows full-screen ads over other apps. Droynis reads Android's usage history for the last 7 days and lists hidden apps that brought a screen of their own to the front. It needs usage access: give it to Droynis in Settings › Apps › Special app access › Usage access, or with the ADB tier.

**What to do:** Uninstall apps listed here unless you opened them yourself, for example a plugin's settings from the app it belongs to. Droynis only reads the history while it scans; to stop that, turn Usage access off for it again.

### SUSP-5004 Apps installed by another app

Warning · Base tier · Android 8.0 and later · fails when an app was installed by another app you installed that isn't an app store or an installer tool

Malware often arrives in two steps: a harmless-looking app, the dropper, later installs the real payload itself, so no app store reviews it. Android records which app installed each app. Droynis lists apps installed by another app you installed, rather than by an app store or Android's own package installer. Installer tools such as SAI and App Manager, and apps that update themselves, are left out.

**What to do:** For each app listed, check that you asked the installing app to install it. If you didn't, uninstall both. If you use an app store Droynis doesn't know, trust it: the apps it installed then stop counting.

### SUSP-5005 Apps with banking-trojan permissions

Warning · Base tier · Android 8.0 and later · fails when an installed app declares an accessibility service and asks for SMS and to draw over other apps (critical when it came from outside an app store or its accessibility service is on)

Banking trojans need three things together: an accessibility service to read the screen and tap for you, SMS access to catch login codes, and drawing over other apps to show fake login screens. Droynis lists installed apps that ask for all three. Automation apps such as Tasker and MacroDroid ask for them too; trust them if you use them.

**What to do:** Uninstall apps listed here that you don't recognize. For one you keep, turn its accessibility service off while you don't need it (Settings › Accessibility) and remove its SMS permission.

### SUSP-5006 Apps signed with a debug or test key

Notice · Base tier · Android 8.0 and later · fails when a user app is signed with Android's debug key or a public test key (warning for a test key, or a debug key on an app that isn't debuggable)

Every app is signed by its developer. Android's debug key is meant for testing on the developer's own phone, and Android's test keys are published with its source code, so anyone can sign with them. Apps from an app store never use either. A finished app re-signed with a debug key is usually a repackaged copy, modded or with malware added; a debuggable one is often a developer's own build.

**What to do:** Uninstall apps listed here unless you built them yourself or know where they came from, and install them again from the developer or an app store.

### SUSP-5007 Known stalkerware and monitoring apps

Warning · Base tier · Android 8.0 and later · fails when an app you installed has the package name or signing key of an app on Echap's Stalkerware Indicators list (critical for stalkerware, warning for a monitoring app that doesn't hide)

Stalkerware is an app someone installs on another person's phone to secretly read their messages, follow their location or listen in. It usually hides its icon and poses as a system service. Droynis compares every app you installed with Stalkerware Indicators, a public list by Echap of the package names and signing keys of known stalkerware, and of monitoring apps that don't hide, such as child-monitoring and family-locator apps. The list ships with Droynis and works offline. A new or rebuilt stalkerware app won't be on it, so a pass means no known stalkerware, not none at all.

**What to do:** If you didn't install a listed app yourself, someone with access to your phone may be watching you. Removing it can alert them, so if you might be in danger, first talk to a support organization for domestic violence or stalking (the Coalition Against Stalkerware lists some at stopstalkerware.org). Then remove its device admin access (APPS-4002) if it has any, uninstall it, and change your account passwords from another device. Mark a monitoring app you set up on purpose as trusted.

### SUSP-5101 Hidden apps running in the background

Warning · ADB tier · Android 10 and later · fails when an app that hides from the app drawer, or one without an icon from outside an app store, runs a service it started, or started a foreground service or drew over other apps in the last 7 days (critical when it hides and came from outside an app store)

Lists apps without a visible app drawer icon that run a service they started themselves right now, or that started a foreground service or drew over other apps in the last 7 days. Adware keeps running this way to show ads. SUSP-5002 sees only what apps declare; this check sees what they do. Services that Android or another app only binds to, such as a keyboard's, are left out. Android shows running services and the app-ops history only to the ADB or Shizuku tier.

**What to do:** Uninstall apps listed here that you don't recognize. Force stop in the app's App info ends it until it starts itself again.

### SUSP-5102 Background camera, microphone and location use

Notice · ADB tier · Android 10 and later · fails when a user app used the camera, microphone or location from the background in the last 7 days (warning for camera or microphone)

Lists user-installed apps that used the camera, the microphone or your location while you were not using them, in the last 7 days. Spyware works this way; so do fitness, navigation and smart-home apps, so check that each one is expected. Android keeps this record in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** For each app listed, open Settings › Apps › the app › Permissions. Set Location to "Allow only while using the app" or "Don't allow", and remove Camera and Microphone from apps that don't need them. Uninstall apps you don't recognize.

### SUSP-5103 Apps that can record the screen without asking

Warning · ADB tier · Android 10 and later · fails when a user app may record or cast the screen without asking

Android asks each time an app wants to record or cast the screen. An app whose PROJECT_MEDIA app-op is set to allow skips that question, and can capture everything on the screen, passwords and messages included, whenever it likes. Settings has no switch for this: it is set from a computer with adb, the way stalkerware and remote-access tools are often set up on someone else's phone. Android keeps this in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Uninstall apps listed that you don't recognize. For an app you keep, take the access back from a computer with adb: put the app's package name, shown in the evidence, in the command below. The app then asks again before each recording.

### SUSP-5104 Background SMS, call log and contacts use

Notice · ADB tier · Android 10 and later · fails when a user app read SMS, the call log or contacts, or received SMS, from the background in the last 7 days (warning when it came from outside an app store)

Lists apps you installed that read your SMS, call log or contacts, or received SMS, while you weren't using them, in the last 7 days. Stalkerware sends these out in the background; so do apps that sync messages to a computer, such as KDE Connect, so check that each one is expected. Your default SMS and phone apps are left out for what their role needs. Android keeps this record in its app-ops service, which only the ADB or Shizuku tier can read.

**What to do:** Open Settings › Apps › the app › Permissions and remove SMS, Call logs and Contacts from apps that don't need them. Uninstall apps you don't recognize.

## Network and radios

| ID | Check | Severity | Fails when |
|---|---|---|---|
| **[Base](#base-tier)** | | | |
| [NETW-3001](#netw-3001-private-dns) | Private DNS (Android 9+) | Warning | DNS isn't encrypted and no VPN is active |
| [NETW-3002](#netw-3002-vpn) | VPN | Info | no VPN is active |
| [NETW-3003](#netw-3003-user-ca-certificates) | User CA certificates | Warning | a user-installed CA certificate can intercept TLS |
| [NETW-3004](#netw-3004-bluetooth) | Bluetooth | Notice | Bluetooth is on |
| [NETW-3005](#netw-3005-wi-fi-security) | Wi-Fi security (Android 12+) | Warning | the phone is on an open or WEP Wi-Fi network without a VPN |
| [NETW-3006](#netw-3006-nfc) | NFC | Info | NFC is on |
| [NETW-3007](#netw-3007-http-proxy) | HTTP proxy | Warning | web traffic on Wi-Fi, mobile data or another network goes through an HTTP proxy |
| [NETW-3008](#netw-3008-location) | Location | Notice | Location is on |
| [NETW-3009](#netw-3009-wi-fi-and-bluetooth-scanning) | Wi-Fi and Bluetooth scanning | Notice | Wi-Fi or Bluetooth scanning is on |
| [NETW-3010](#netw-3010-2g-mobile-networks) | 2G mobile networks | Notice | a SIM in use may connect to 2G networks |
| [NETW-3011](#netw-3011-secure-nfc) | Secure NFC (Android 10+) | Notice | NFC is on and works while the phone is locked |
| [NETW-3012](#netw-3012-added-system-ca-certificates) | Added system CA certificates | Warning | a CA certificate was added to the system store, which every app trusts (by a root module or a modified system) |
| **[ADB](#adb-tier)** | | | |
| [NETW-3101](#netw-3101-wi-fi-mac-randomization) | Wi-Fi MAC randomization (Android 10+) | Notice | the current Wi-Fi connection or a saved network uses the phone's own MAC address |
| [NETW-3102](#netw-3102-open-wi-fi-networks-that-join-automatically) | Open Wi-Fi networks that join automatically (Android 12+) | Notice | a saved open, Enhanced Open or WEP network joins automatically |
| [NETW-3103](#netw-3103-hotspot-security) | Hotspot security (Android 14+) | Notice | the hotspot has no password (a warning), or doesn't turn off by itself when no device is connected |
| [NETW-3104](#netw-3104-hidden-wi-fi-networks) | Hidden Wi-Fi networks (Android 12+) | Notice | a saved Wi-Fi network is hidden, so the phone calls out its name when it looks for Wi-Fi |
| **[Shizuku](#shizuku-tier)** | | | |
| [NETW-3201](#netw-3201-always-on-vpn-lockdown) | Always-on VPN lockdown | Notice | an always-on VPN lets traffic out while it is down |
| [NETW-3202](#netw-3202-mobile-network-encryption) | Mobile network encryption (Android 14+) | Notice | the phone accepts mobile connections without encryption (Require encryption is off) |
| [NETW-3203](#netw-3203-mobile-network-security-alerts) | Mobile network security alerts (Android 15+) | Notice | the phone doesn't warn about signs of a fake cell tower (Network notifications are off) |
| **[Root](#root-tier)** | | | |
| [NETW-3301](#netw-3301-apps-listening-on-the-network) | Apps listening on the network | Notice | a user app accepts connections from the network |

### NETW-3001 Private DNS

Warning · Base tier · Android 9 and later · fails when DNS isn't encrypted and no VPN is active

Without Private DNS, every website and app domain you look up is sent in plain text. The Wi-Fi owner or the mobile carrier can log those lookups or answer them with fake ones. Private DNS (DNS over TLS) encrypts them.

**What to do:** Open Private DNS (Settings › Network & internet; the location varies by vendor), choose "Private DNS provider hostname" and enter a privacy-respecting resolver such as dns.quad9.net.

### NETW-3002 VPN

Info · Base tier · Android 8.0 and later · fails when no VPN is active

A VPN encrypts traffic between this phone and the VPN server, hiding it from the local network and the carrier. It moves that trust to the VPN provider, so pick one with an audited no-logs policy, or host your own.

**What to do:** Use a trustworthy VPN, especially on public Wi-Fi. Under Settings › Network & internet › VPN you can also turn on "Always-on VPN" and "Block connections without VPN".

### NETW-3003 User CA certificates

Warning · Base tier · Android 8.0 and later · fails when a user-installed CA certificate can intercept TLS

An installed certificate authority can be used to decrypt the TLS traffic of apps that trust user certificates, for example on a school or company network that inspects traffic. One you did not knowingly install is a red flag.

**What to do:** Under Settings › Security › Encryption & credentials › Trusted credentials › User, remove certificates you do not need (the location varies by vendor).

### NETW-3004 Bluetooth

Notice · Base tier · Android 8.0 and later · fails when Bluetooth is on

A radio that is on can be attacked: Bluetooth flaws such as BlueBorne and BLUFFS let nearby attackers reach a phone without pairing. Leaving it on also makes the device easier to notice and track nearby.

**What to do:** Turn Bluetooth off when you are not using headphones, a watch or a car.

### NETW-3005 Wi-Fi security

Warning · Base tier · Android 12 and later · fails when the phone is on an open or WEP Wi-Fi network without a VPN

On an open or WEP Wi-Fi network anyone in range can record the traffic and set up a look-alike network. HTTPS still protects page contents, but plain DNS lookups and badly written apps leak.

**What to do:** Avoid open and WEP networks or use a VPN on them, and forget saved open networks so the phone does not rejoin them by itself.

### NETW-3006 NFC

Info · Base tier · Android 8.0 and later · fails when NFC is on

NFC talks to cards, payment terminals and tags held a few centimeters away. The short range makes attacks rare, but switching it off when you do not pay by phone closes one more way in.

**What to do:** Turn NFC off if you do not use contactless payments, transit cards or NFC tags.

### NETW-3007 HTTP proxy

Warning · Base tier · Android 8.0 and later · fails when web traffic on Wi-Fi, mobile data or another network goes through an HTTP proxy

An HTTP proxy receives the web traffic of every app that honours it. A proxy you did not set up yourself, added by an app, a management profile, a Wi-Fi network or a mobile data access point (APN), can log the sites you visit and tamper with unencrypted pages. Droynis looks at Wi-Fi and at mobile data, which stays connected next to Wi-Fi on most phones.

**What to do:** If you do not recognise the proxy, remove it. For Wi-Fi, open the network's details and set Proxy to None. For mobile data, open Access point names (under Mobile network), pick the one in use and clear Proxy and Port, or reset to default. An operator's own APN proxy is expected, but it still sees your unencrypted traffic.

### NETW-3008 Location

Notice · Base tier · Android 8.0 and later · fails when Location is on

With Location on, every app you allowed can see where you are, and the phone's location services may keep collecting Wi-Fi and cell data in the background. Turning it off when you don't need it is the simplest way to stop being tracked.

**What to do:** Turn Location off in Quick Settings when you don't need it. Under Settings › Location › App location permissions, keep "Allow all the time" only for apps that really need it.

### NETW-3009 Wi-Fi and Bluetooth scanning

Notice · Base tier · Android 8.0 and later · fails when Wi-Fi or Bluetooth scanning is on

With these on, the phone keeps scanning for Wi-Fi networks and Bluetooth devices even when you turn Wi-Fi and Bluetooth off, to help locate you. The radios stay active, so turning them off doesn't close their attack surface or stop location from working.

**What to do:** Turn off Wi-Fi scanning and Bluetooth scanning under Settings › Location › Location services (on older Android: Location › Scanning).

### NETW-3010 2G mobile networks

Notice · Base tier · Android 8.0 and later · fails when a SIM in use may connect to 2G networks

2G (GSM) never checks that a cell tower is genuine, and its encryption is weak or can be switched off. Fake base stations (IMSI catchers and "SMS blasters") pull nearby phones down to 2G to locate them, listen to calls, read texts or send scam SMS. With 2G off the phone ignores them; where an operator still relies on 2G, coverage can suffer. Android 12 and later hide this setting from apps, so there Droynis reads it with Shizuku or root.

**What to do:** On Android 12 and later turn off Allow 2G (Settings › Network & internet › SIMs, or Mobile network; the place varies by vendor). Where there is no such switch, set Network mode to one without 2G, such as LTE/3G or 5G/LTE. Advanced Protection turns 2G off too.

### NETW-3011 Secure NFC

Notice · Base tier · Android 10 and later · fails when NFC is on and works while the phone is locked

With NFC on, a locked phone still answers card readers held close to it: transit cards and some payment apps work without unlocking. Requiring an unlock for NFC (Secure NFC) keeps payments and transit cards for when the phone is unlocked, so someone who holds a reader to your pocket, or takes the phone, can't use them.

**What to do:** Open Settings › Connected devices › Connection preferences › NFC and turn on "Require device unlock for NFC" ("Secure NFC" on older Android). If you don't use NFC, turn it off.

### NETW-3012 Added system CA certificates

Warning · Base tier · Android 8.0 and later · fails when a CA certificate was added to the system store, which every app trusts (by a root module or a modified system)

Android comes with about 150 trusted certificate authorities (CAs). Every app trusts that system list, while most apps ignore CAs you install yourself. Root modules and app-testing tools (Burp Suite, mitmproxy, HTTP Toolkit) can add a CA to the system list, and then whoever holds its key can read and change the encrypted traffic of every app. A clean result means no sign of an added CA was found: one written into a modified system image with an old date can't be told apart.

**What to do:** If you added it to inspect app traffic, remove the root module or tool once you're done. If you didn't, turn the certificate off under Settings › Security › Encryption & credentials › Trusted credentials › System, uninstall root modules you don't recognize, or reinstall the official firmware.

### NETW-3101 Wi-Fi MAC randomization

Notice · ADB tier · Android 10 and later · fails when the current Wi-Fi connection or a saved network uses the phone's own MAC address

Every Wi-Fi network the phone joins sees its MAC address. The phone's own address is the same everywhere, so the networks, and whoever runs several of them, can recognize the phone and link its visits. Android uses a random address for each network unless that network is set to use the device MAC. Android keeps this in its Wi-Fi service, which only the ADB, Shizuku or root tier can read.

**What to do:** Open Settings › Network & internet › Internet (or Wi-Fi), tap the gear next to each network listed, then Privacy, and choose "Use randomized MAC". Some company and carrier networks need the device MAC; mute this check if only those are left.

### NETW-3102 Open Wi-Fi networks that join automatically

Notice · ADB tier · Android 12 and later · fails when a saved open, Enhanced Open or WEP network joins automatically

A network without a password, open, Enhanced Open or WEP, proves nothing about who runs it: anyone can set up one with the same name, and a phone that joins it by itself hands that person its traffic, DNS and sign-in pages. Enhanced Open encrypts the radio link, but not against whoever runs the access point. Android keeps the saved networks in its Wi-Fi service, which only the ADB, Shizuku or root tier can read.

**What to do:** Open Settings › Network & internet › Internet (or Wi-Fi) › Saved networks, tap each network listed and turn off "Automatically connect", or forget it. Join such networks by hand, with a VPN.

### NETW-3103 Hotspot security

Notice · ADB tier · Android 14 and later · fails when the hotspot has no password (a warning), or doesn't turn off by itself when no device is connected

While the hotspot is on, every device that joins it uses your mobile data and shares a network with your phone. Without a password (security None, or Enhanced Open, which only encrypts the radio link) anyone in range can join. A hotspot that turns itself off once no device is connected isn't left on by accident. Android keeps these settings in its Wi-Fi service, which only the ADB, Shizuku or root tier can read.

**What to do:** Open Settings › Network & internet › Hotspot & tethering › Wi-Fi hotspot. Set Security to WPA3-Personal, or WPA2/WPA3-Personal if older devices must join, with a long password, and turn on "Turn off hotspot automatically".

### NETW-3104 Hidden Wi-Fi networks

Notice · ADB tier · Android 12 and later · fails when a saved Wi-Fi network is hidden, so the phone calls out its name when it looks for Wi-Fi

A hidden network doesn't announce its name, so a phone that saved one calls out that name when it looks for Wi-Fi, wherever it is. Anyone nearby can log the name to recognize and follow the phone or learn where you live or work, and can set up an access point with the same name to lure the phone in. Hiding a network adds no security: its name still shows in the traffic of every device that uses it. Android keeps the saved networks in its Wi-Fi service, which only the ADB, Shizuku or root tier can read.

**What to do:** On the router, make the network visible again (turn off "Hide SSID" or "Hidden network"). Then forget the network on the phone and join it again, so Android stops calling out its name: Settings › Network & internet › Internet (or Wi-Fi) › Saved networks. Forget hidden networks you no longer use.

### NETW-3201 Always-on VPN lockdown

Notice · Shizuku tier · Android 8.0 and later · fails when an always-on VPN lets traffic out while it is down

An always-on VPN starts with the phone and stays connected. Only with "Block connections without VPN" does traffic also stop while the VPN is down or reconnecting; without it, apps quietly use the normal network. Apps can't see which app is the always-on VPN, but the shell user Shizuku runs as can.

**What to do:** Open Settings › Network & internet › VPN, tap the gear next to your VPN, and turn on both "Always-on VPN" and "Block connections without VPN".

### NETW-3202 Mobile network encryption

Notice · Shizuku tier · Android 14 and later · fails when the phone accepts mobile connections without encryption (Require encryption is off)

Calls, texts and mobile data are encrypted between the phone and the cell tower, but the network can tell the phone to turn that off (a "null cipher"). Fake cell towers (IMSI catchers) do exactly this to read texts, login codes included, and listen to calls. From Android 14, phones whose modem supports it can refuse such connections; Settings calls it "Require encryption". A few operators still use unencrypted connections, so with it on the phone may lose service in places; emergency calls never need encryption.

**What to do:** Turn on Require encryption: Settings › Security & privacy › More security & privacy › Mobile network security on Android 15 and later, or Settings › Network & internet › SIMs › your SIM on Android 14 (the place varies by vendor). If calls or data stop working where you live, turn it off again. Turning off Allow 2G (NETW-3010) blocks the most common way to force a weak connection too.

### NETW-3203 Mobile network security alerts

Notice · Shizuku tier · Android 15 and later · fails when the phone doesn't warn about signs of a fake cell tower (Network notifications are off)

From Android 15, phones whose modem supports it can warn you when the network asks for your SIM's or phone's identity in the clear, or turns encryption off: both are signs of a fake cell tower (IMSI catcher) nearby. Settings calls these "Network notifications". A warning doesn't stop the attack, but tells you to keep sensitive calls and texts for later, or to switch to airplane mode.

**What to do:** Turn on Network notifications: Settings › Security & privacy › More security & privacy › Mobile network security (the place varies by vendor).

### NETW-3301 Apps listening on the network

Notice · Root tier · Android 8.0 and later · fails when a user app accepts connections from the network

An app that listens on a network port accepts connections from other devices on the same network, such as everyone on a public Wi-Fi. SSH servers, file sharing and sync apps do this on purpose; a bug in them is then reachable by anyone nearby. Since Android 10 apps can't see each other's ports; root can.

**What to do:** Stop the server in apps that don't need to be reachable, or use it only on networks you trust. Uninstall apps you don't recognize.
