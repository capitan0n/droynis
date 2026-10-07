# Releasing

## Once

1. Create the release key and back it up offline with its passwords: an app signed with another key
   can't update it, so losing the key means every user reinstalls.

   ```sh
   keytool -genkeypair -v -keystore droynis-release.jks -alias droynis -keyalg RSA -keysize 4096 -validity 10000
   ```

2. Repository › Settings › Secrets and variables › Actions, add `KEYSTORE_BASE64`
   (`base64 -w0 droynis-release.jks`), `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD`.
3. Optional: Settings › Environments › `release` › Required reviewers, so each release waits for
   your approval before it can use the key.

For a local signed build, put the same four values in `keystore.properties` (`storeFile`,
`storePassword`, `keyAlias`, `keyPassword`); it is git-ignored.

## Each release

1. Raise `versionCode` and `versionName` in `app/build.gradle.kts`.
2. Write `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` (500 characters at most): it
   becomes the release notes here and the changelog on F-Droid.
3. `./gradlew check`, commit, then tag and push:

   ```sh
   git tag -a v1.2.3 -m "Droynis 1.2.3"
   git push origin main v1.2.3
   ```

The **Release** workflow checks that the tag matches `versionName`, runs the tests, builds and signs
the APK, refuses it if it requests `INTERNET`, attests its provenance and publishes
`droynis-1.2.3.apk` with its `.sha256`. A tag with a hyphen (`v1.3.0-rc1`) becomes a pre-release.
The **Reproducible build** workflow builds the tag twice, from two directories, and compares.

## F-Droid

F-Droid reads the descriptions, changelogs, icon and screenshots from `fastlane/metadata` in the
tagged source and builds the unsigned release itself. While the reproducible build passes, F-Droid
can ship the APK signed here: its metadata then names the release download (`Binaries`) and the
certificate SHA-256 from the release notes (`AllowedAPKSigningKeys`).
