#!/bin/bash
# pull_all_apps.sh — Pull all installed apps (APKs) from an Android device using adb.

set -euo pipefail

if ! command -v adb &>/dev/null; then
  echo "Error: adb not found. Please install Android Platform Tools."
  exit 1
fi

if ! adb get-state 1>/dev/null 2>&1; then
  echo "Error: No device detected. Please connect a device and enable USB debugging."
  exit 1
fi

OUTPUT_DIR="pulled_apks"
mkdir -p "$OUTPUT_DIR"

echo "Fetching list of installed packages..."
mapfile -t PACKAGES < <(adb shell pm list packages | sed 's/package://g' | tr -d '\r')

TOTAL=${#PACKAGES[@]}
echo "Found $TOTAL packages."
echo

INDEX=1
for PACKAGE_NAME in "${PACKAGES[@]}"; do
  [[ -z "$PACKAGE_NAME" ]] && continue

  echo "[$INDEX/$TOTAL] Pulling APK(s) for: $PACKAGE_NAME"

  DEST_DIR="$OUTPUT_DIR/$PACKAGE_NAME"
  mkdir -p "$DEST_DIR"

  # Get APK paths for this package
  mapfile -t APK_PATHS < <(adb shell pm path "$PACKAGE_NAME" | sed 's/package://g' | tr -d '\r')

  if [[ ${#APK_PATHS[@]} -eq 0 ]]; then
    echo "  ⚠️ No APKs found for $PACKAGE_NAME"
    ((INDEX++))
    continue
  fi

  N=1
  for APK_PATH in "${APK_PATHS[@]}"; do
    [[ -z "$APK_PATH" ]] && continue
    FILE_NAME="base.apk"
    if [[ ${#APK_PATHS[@]} -gt 1 ]]; then
      FILE_NAME="split_${N}.apk"
    fi
    echo "  -> Pulling $APK_PATH"
    adb pull "$APK_PATH" "$DEST_DIR/$FILE_NAME" >/dev/null || echo "  ⚠️ Failed to pull $APK_PATH"
    ((N++))
  done

  echo "Saved to $DEST_DIR"
  echo
  ((INDEX++))
done

echo "✅ All APKs pulled successfully into '$OUTPUT_DIR/'"
