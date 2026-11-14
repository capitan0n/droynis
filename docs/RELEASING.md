# Releasing Droynis

A release is a signed APK on GitHub, built by the [Release workflow](../.github/workflows/release.yml)
from a tag, and the same version on F-Droid, built there from the same tag. Nothing is built or
signed on your own computer.

## Once

1. Create the signing key and back it up offline. Android refuses an update signed with another
   key, so a lost key means every user has to uninstall and reinstall.

   ```sh
   keytool -genkeypair -v -keystore droynis-release.jks -alias droynis -keyalg RSA -keysize 4096 -validity 10000
   ```

2. Add the Actions secrets `KEYSTORE_BASE64` (`base64 -w0 droynis-release.jks`), `KEYSTORE_PASSWORD`,
   `KEY_ALIAS` and `KEY_PASSWORD`.
3. In the repository settings, add required reviewers to the `release` environment, so each release
   waits for an approval.
4. The workflow compares the APK's signing certificate with `EXPECTED_CERTIFICATE` in
   `release.yml` and stops when they differ. Change that value only if the key itself changes.

## Each release

1. Raise `versionCode` and `versionName` in `app/build.gradle.kts`. A pre-release has a suffix,
   such as `1.3.0-rc1`.
2. Write `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt`, at most 500 characters.
   It becomes the GitHub release notes, the F-Droid changelog and the app's "What's new" dialog.
   CI fails without it (`ci/check-changelog.sh`). Add the translated ones
   (`fastlane/metadata/android/zh-TW/changelogs/`) when you have them.
3. If checks changed, regenerate the catalog and update the counts in `README.md`:

   ```sh
   UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test
   ```

4. If a permission was added or removed on purpose, update `ci/release-permissions.txt`. CI fails
   when the release APK requests anything that file doesn't list.
5. If a dependency changed and `gradle/verification-metadata.xml` exists, regenerate it (below).
6. Run `./gradlew check`.
7. Run the **Instrumented tests** workflow by hand on the release commit and wait for it: it is the
   only place the real probes and the UI run on Android 8 to 17.
8. Refresh the screenshots in `fastlane/metadata/android/en-US/images/phoneScreenshots/` when the
   UI or the number of checks changed.
9. Tag and push:

   ```sh
   git tag -a v1.2.3 -m "Droynis 1.2.3"
   git push origin main v1.2.3
   ```

## What the tag starts

- **Release**: checks that the tag matches `versionName` and that the changelog exists, runs
  `./gradlew check assembleRelease` without any cache, checks the APK's permissions and signing
  certificate, attests where it was built and publishes the GitHub release with its SHA-256.
- **Reproducible build**: builds the unsigned APK twice from two directories and compares them. It
  also runs every week and on pull requests that touch the build, so a tag is not the first time
  you hear about it.

F-Droid picks the tag up by itself and publishes a few days later.

## After

- Check the release page: the APK, its `.sha256`, the certificate fingerprint in the notes.
- `gh attestation verify droynis-<version>.apk --repo capitan0n/droynis` should pass.
- If something is wrong, delete the GitHub release, fix it and release a new version. Never move a
  tag that F-Droid may already have built.

## Dependency verification

`gradle/verification-metadata.xml` lists the SHA-256 of every plugin and library the build
downloads. While the file exists, Gradle refuses an artifact that doesn't match, so a tampered
dependency fails the build instead of reaching the APK. Without the file Gradle verifies nothing.

To create or refresh it, run the **Dependency verification metadata** workflow by hand, download
its artifact, read the diff and commit the file as `gradle/verification-metadata.xml`. Locally:

```sh
./gradlew --no-configuration-cache --write-verification-metadata sha256 \
    check assembleDebug assembleRelease assembleDebugAndroidTest
```

Things to know:

- Every Dependabot update changes checksums, so its pull request fails until the file is
  regenerated on that branch. That is the point: a new artifact is looked at before it is trusted.
- The Android Gradle plugin downloads `aapt2` for the computer it runs on. A file written on Linux
  lacks the macOS and Windows ones; run the command above on those systems too (it adds to the
  file), or build there with `--dependency-verification lenient`.
- Android Studio also downloads sources and javadoc, which the file doesn't list. Add
  `<trust file=".*-javadoc[.]jar" regex="true"/>` and `<trust file=".*-sources[.]jar" regex="true"/>`
  under `<trusted-artifacts>` in the file's `<configuration>`.
- Checksums prove that an artifact did not change since you first saw it, not that it was good
  then. Signature verification (`--write-verification-metadata pgp,sha256`) is stricter, and more
  work to keep up.
