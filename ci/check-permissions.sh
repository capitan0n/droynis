#!/usr/bin/env bash
# Fails unless the APK requests exactly the permissions listed in ci/release-permissions.txt.
# Usage: ci/check-permissions.sh <apk>    (AAPT2 overrides the aapt2 found in $ANDROID_HOME)
set -euo pipefail

apk="${1:?usage: $0 <apk>}"
allowlist="$(dirname "$0")/release-permissions.txt"

if [ -z "${AAPT2:-}" ]; then
  AAPT2="$(printf '%s\n' "${ANDROID_HOME:?ANDROID_HOME is not set}"/build-tools/*/ | sort -V | tail -n 1)aapt2"
fi

dump="$("$AAPT2" dump permissions "$apk")"
printf '%s\n' "$dump"

# aapt2 prints one "uses-permission: name='…'" line per request (also uses-permission-sdk-23).
requested="$(printf '%s\n' "$dump" | sed -n "s/^uses-permission[^:]*: name='\([^']*\)'.*/\1/p" | LC_ALL=C sort -u)"
allowed="$(grep -v '^#' "$allowlist" | sed 's/[[:space:]]*$//' | sed '/^$/d' | LC_ALL=C sort -u)"

if [ -z "$requested" ]; then
  echo "::error::No permissions could be read from $apk; has the output of aapt2 changed?"
  exit 1
fi
if printf '%s\n' "$requested" | grep -qx "android.permission.INTERNET"; then
  echo "::error::$apk requests android.permission.INTERNET"
  exit 1
fi

added="$(comm -23 <(printf '%s\n' "$requested") <(printf '%s\n' "$allowed"))"
removed="$(comm -13 <(printf '%s\n' "$requested") <(printf '%s\n' "$allowed"))"
if [ -n "$added" ]; then
  echo "::error::$apk requests permissions that are not in $allowlist: $(echo $added)"
fi
if [ -n "$removed" ]; then
  echo "::error::$allowlist lists permissions that $apk no longer requests: $(echo $removed)"
fi
[ -z "$added$removed" ]
echo "Permissions match $allowlist"
