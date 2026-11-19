# Droynis — Dark Orchid

Extract the whole ZIP and open **main.html**. No install, build step or local server is needed. The five pages use normal relative links and work through file://. Local screenshots, fonts, styles and scripts are included. External download and project links require internet only when followed.

## Five pages

- author.html — Alexandros’s background, other projects and GitHub profile.
- main.html — the introduction, the three-column principles from ZIP 1, real app screenshot gallery and all five audit areas.
- checks.html — all 108 documented check definitions, searchable and filterable by category, access tier and severity. Filters combine. Clear filters resets all selections. The first 12 matching checks show initially; Show all expands the rest.
- guide.html — practical scan workflow, access tiers and ADB commands, scoring weights, muting and trusting, reports and scheduled scans.
- install.html — download options, checksum and build-attestation instructions, FAQs and project/contribution/security links.

## Visual changes

Dark plum theme throughout. The level yellow message box sits below both phone screens, without covering either screen. Warning is yellow, Critical red, Info green and Notice lavender. Access tier labels have separate colors: Base blue, ADB turquoise, Shizuku purple and Root orange. All labels remain readable as text; meaning does not depend on color alone.

The tier filter shows checks assigned to that particular tier, not a cumulative count. In the Android app, higher tiers include earlier-tier checks. Category, search, tier and severity filters are applied together.

## Code

main.html / checks.html / guide.html / install.html / author.html — page content.
style.css — local fonts and all responsive styling.
site.js — menu, filter logic, tier tabs, copy controls and screenshot viewer.
catalog.js — 108 real check definitions from the bundled docs/CHECKS.md.
assets/ — repository screenshots and icon; local fonts and license notices.
docs/, SOURCES.md, LICENSE — factual sources, attribution and GPL-3.0-or-later license.

No remote font service, analytics, forms, backend, service workers, module imports or fetch calls. The website does not scan your device. The beta check catalog comes from commit a5f6c837925cb6d8267c1e4838b5e86354ab1bff. Logo credits and the original check catalog are bundled.

The circular owl favicon cycles through three local rim colors while the page is visible. Reduced-motion preferences keep it still.
