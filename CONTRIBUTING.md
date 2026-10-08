# Contributing

The most useful help is a report of a wrong result: use the "Wrong result" issue form and attach a
JSON report (⋮ › Save report (JSON), with Hide personal details on).

## Rules every check follows

- Read-only: never change a setting, never ask for `INTERNET`.
- Never a false PASS: a value that can't be read is Unknown, a feature that doesn't exist is N/A.
- No identifiers: no IMEI, serial, phone number, account or user names in evidence. Values that
  identify a network or a computer (DNS, proxies, hosts) get `personal = true`.
- Check logic lives in the pure-Kotlin modules (`core/`, `checks/`) and is tested with fakes; only
  `platform/android` calls the framework.

## Adding a check

1. A class in the tier's module (`checks/base`, `checks/adb`, …) with a `CheckSpec`: a stable id
   (`AREA-NNNN`, never reused), the explanation, the fix and `failsWhen`.
2. One line in that tier's registry (`baseChecks()`, `adbChecks()`, …).
3. Tests with fake probes, then `UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test` to regenerate
   docs/CHECKS.md.
4. `./gradlew check` must pass.

## Pull requests

Keep them small and say how you tested: phone, Android version, tier. Contributions are licensed
under the project's license, GPL-3.0-or-later ([LICENSE](LICENSE)).
