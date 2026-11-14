# Contributing

Thanks for helping. The most useful contributions, in order:

1. **Report a wrong result.** A check passed, failed or stayed Unknown when it shouldn't have.
2. **Translate** the app.
3. **Fix a bug or add a check.**

Security problems go to [SECURITY.md](SECURITY.md), not to a public issue.

## Report a wrong result

Use the [Wrong result](https://github.com/capitan0n/droynis/issues/new?template=wrong-result.yml)
issue form. It helps most with:

- the check id (shown on the check's page, e.g. `ACCS-2020`),
- what Droynis says and what is true, with a Settings screenshot or an `adb` command that shows it,
- the phone, Android version, Droynis version and tier,
- a JSON report: **⋮ › Save report (JSON)**, with **Hide personal details** on.

## Translate

App texts are in `app/src/main/res/values/strings.xml`. Copy it to `values-<language>/strings.xml`
(see `values-zh-rTW` for an example) and translate the values, keeping placeholders such as `%1$s`.
Check titles, explanations and fixes are still English Kotlin strings, so they aren't translatable
yet.

## Build and test

You need JDK 21 and the Android SDK (compileSdk 37).

```sh
./gradlew check            # unit tests, lint, and docs/CHECKS.md matching the code
./gradlew assembleDebug    # app/build/outputs/apk/debug/app-debug.apk
./gradlew :checks-base:test  # one module's tests, in seconds
```

Check logic lives in plain Kotlin modules (`core/`, `checks/`) and is tested with fake probes, no
emulator needed. Only `platform/android` calls the Android framework. [docs/DESIGN.md](docs/DESIGN.md)
explains the layout and why.

## Rules every check follows

- **Read-only:** never change a setting, never ask for `INTERNET`.
- **Never a false PASS:** a value it can't read is Unknown; a feature the phone lacks is N/A.
- **No identifiers:** no IMEI, serial, phone number, account or user names in evidence. Values that
  point to a network or a computer (DNS, proxies, hosts, Wi-Fi names) get `personal = true`.
- **Explain itself:** every finding names what it read (`Source`) and says what to do.

## Add a check

1. Pick the module for its tier: `checks/base`, `checks/adb`, `checks/shizuku` or `checks/root`.
2. Write a class with a `CheckSpec`: a new id, title, severity, explanation, fix and `failsWhen`.
   Ids are `AREA-NNNN` and never reused. The area is `INTG` (1xxx), `ACCS` (2xxx), `NETW` (3xxx),
   `APPS` (4xxx) or `SUSP` (5xxx); the hundreds digit is the tier: 0 base, 1 ADB, 2 Shizuku,
   3 root (e.g. `ACCS-2201` is a Shizuku check).
3. Add one line to that tier's registry (`baseChecks()`, `adbChecks()`…), in category order.
4. If it needs a new framework call, add a probe method and implement it in `platform/android`.
5. Write tests with fake probes, including the Unknown case.
6. Regenerate the catalog, then run everything:

   ```sh
   UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test
   ./gradlew check
   ```

## Update the stalkerware list

SUSP-5007 uses Echap's [Stalkerware Indicators](https://github.com/AssoEchap/stalkerware-indicators)
(CC BY 4.0), built into the app. To refresh it (needs PyYAML):

```sh
git clone --depth 1 https://github.com/AssoEchap/stalkerware-indicators /tmp/sw
python3 scripts/update-stalkerware-indicators.py /tmp/sw
```

A new permission, from a manifest or a library, must also be added to `ci/release-permissions.txt`
with a line saying what needs it; CI compares the release APK against that list.

## Pull requests

- Open them against `beta`; `main` holds released code.
- Keep each one to one change, and say how you tested it: phone, Android version, tier.
- `./gradlew check` must pass.

Contributions are licensed under the project's license, GPL-3.0-or-later ([LICENSE](LICENSE)).
