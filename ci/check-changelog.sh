#!/usr/bin/env bash
# Fails unless the current versionCode has an English changelog of at most 500 characters: the
# release notes on GitHub and F-Droid and the app's "What's new" dialog are all built from it.
set -euo pipefail

cd "$(dirname "$0")/.."
code="$(sed -n 's/.*versionCode = \([0-9][0-9]*\).*/\1/p' app/build.gradle.kts | head -n 1)"
if [ -z "$code" ]; then
  echo "::error::No versionCode found in app/build.gradle.kts"
  exit 1
fi
changelog="fastlane/metadata/android/en-US/changelogs/$code.txt"
if [ ! -s "$changelog" ]; then
  echo "::error::$changelog is missing or empty (versionCode $code)"
  exit 1
fi
length="$(LC_ALL=C.UTF-8 wc -m < "$changelog" | tr -d ' ')"
if [ "$length" -gt 500 ]; then
  echo "::error::$changelog has $length characters; F-Droid shows at most 500"
  exit 1
fi
echo "$changelog: $length characters"
