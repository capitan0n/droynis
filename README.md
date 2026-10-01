# Droynis

A Lynis-style security and privacy audit for Android. Droynis inspects the device it runs on,
explains every finding and suggests a fix. It never changes anything itself.

- GPL-3.0, no Google Play Services, no analytics, no network permission.
- Works without root or Shizuku; optional ADB and Shizuku tiers are planned for extra checks.
- Every result shows the raw evidence and the API it came from.

Status: early development. Three base-tier checks are implemented (secure lock screen, security
patch age, USB debugging). See [docs/DESIGN.md](docs/DESIGN.md) for the architecture, the check
contract and notes on what the platform does and does not allow.

## Build

Requires JDK 17+ and the Android SDK (compileSdk 37).

```sh
./gradlew check            # unit tests and lint
./gradlew assembleDebug    # app/build/outputs/apk/debug/app-debug.apk
```

The pure-Kotlin modules (`core-model`, `checks-base`, `report`) hold all check logic and run on
any JVM; only `platform-android` and `app` touch Android APIs.

## License

GNU General Public License v3. See [LICENSE](LICENSE).
