# Releasing Droynis

1. Bump `versionCode` and `versionName` in [app/build.gradle.kts](../app/build.gradle.kts).
2. Write `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt` (up to 500 characters).
   GitHub, F-Droid and the app’s “What’s new” dialog use the same text.
3. If checks changed, regenerate the catalog with `UPDATE_CHECKS_DOC=1 ./gradlew :checks-adb:test`.
   If app permissions changed, update [the release permission list](../ci/release-permissions.txt).
4. Run `./gradlew check`. Run [Instrumented tests](../.github/workflows/instrumented.yml) on
   the release commit and wait for the emulator tests to pass.
5. Tag that commit with `v` followed by the exact `versionName` (for example, `v1.2.3`).
   Push the tag to start the [release workflow](../.github/workflows/release.yml).
6. Download the published APK and its checksum. Follow the [verification steps](../README.md#install)
   to check the checksum and build attestation. If you need to ship a fix, use a new version and tag.
   F-Droid may already have built the previous tag.

## Dependency verification

If `gradle/verification-metadata.xml` is in use and dependencies changed, run the
[metadata workflow](../.github/workflows/dependency-verification.yml) and review the checksum
changes before committing them. For macOS or Windows builds, run the same Gradle command on
that system to include its platform-specific tools.
