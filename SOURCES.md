# Droynis website content sources

General project information and screenshots come from **capitan0n/droynis**, release `v1.1.0`.

- [README.md](https://github.com/capitan0n/droynis/blob/v1.1.0/README.md): purpose, read-only behavior, privacy, Android 8.0+, install sources, optional tiers, reports, scheduling, attribution and license.
- [Release check catalog](https://github.com/capitan0n/droynis/blob/v1.1.0/docs/CHECKS.md) contains all 108 entries. An exact copy is in `docs/CHECKS.md`. The website labels the 11 checks added since v1.0.0.
- [docs/DESIGN.md](https://github.com/capitan0n/droynis/blob/v1.1.0/docs/DESIGN.md): score, evidence, Unknown/N/A handling, profile and OS limitations, fixed privileged reads and no-network enforcement.
- [art/droynis-icon.svg](https://github.com/capitan0n/droynis/blob/v1.1.0/art/droynis-icon.svg): original project icon, unchanged.
- [Repository screenshots](https://github.com/capitan0n/droynis/tree/v1.1.0/fastlane/metadata/android/en-US/images/phoneScreenshots): original dashboard, check list and finding screenshots, unchanged. The screenshots show example device results and may predate the present catalog. Their numbers are not represented as the current catalog count or a live visitor audit.

The website is a presentation of Droynis, not a browser-based audit. No device-scanning functionality is claimed. The terminal walkthrough (where present) illustrates the documented audit flow; it is not a CLI command or device scan.

## Facts used

The 1.1.0 catalog lists 108 entries, including one inactive check, across five areas. Device integrity has 21, access control 18, apps and permissions 32, suspicious apps 14, and network and radios 23. Assigned access tiers are Base 72, ADB 18, Shizuku 9 and Root 9.

Droynis is a read-only audit, not an antivirus. It has no INTERNET permission, analytics or Google Play Services dependency. Optional Markdown/JSON export and scheduled scans are documented. Root remains off until enabled. Findings open Settings; the app does not change settings itself.

## Rights and credits

Droynis, its logo and repository screenshots: Alexandros (capitan0n), GPL-3.0-or-later. Full upstream LICENSE is bundled. This website's original HTML, CSS and JavaScript are also offered under GPL-3.0-or-later.

Open Sans, Noto Serif and DejaVu Sans Mono fonts are locally bundled as subsets. Their copyright and license notices are in `assets/fonts/`. No remote font service is used.

Version 1.1.0 removed the known-stalkerware detector and its list. SUSP-5007 remains in the catalog as inactive.

Download logo sources and credits are in `assets/brands/SOURCES.txt`.

The author biography and earlier project descriptions come from [Alexandros’s profile README](https://github.com/capitan0n/capitan0n/blob/main/README.md), blob `849bbcb3799aa4120cacc847443ae762b2a05f79`.

The home page links to [Andy Walker’s hands-on article in Android Authority](https://www.androidauthority.com/droynis-open-source-android-security-app-3731115/), published November 8, 2026. The article opens only when a reader follows the link.

The local circular favicon frames adapt the bundled Droynis owl artwork.

The audiotap description is based on its [project README](https://github.com/capitan0n/audiotap/blob/main/README.md). The bundled copy of the Droynis README omits the personal email address.
