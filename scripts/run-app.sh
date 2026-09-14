#!/usr/bin/env bash
# Build the signed MacAudit.app from the current tree and launch it.
#
# Chains the three manual steps from the README (engine → xcframework +
# bindings, xcodegen, xcodebuild) and opens the result. Builds are signed with
# the Apple Development identity from apps/MacAudit/project.yml, so macOS
# keeps its folder-access grants across rebuilds (an ad-hoc build, which is
# what CI's CODE_SIGNING_ALLOWED=NO produces, re-prompts every time).
#
#   scripts/run-app.sh [--release] [--fake] [--no-open] [--no-ffi]
#
#   --release   optimized engine + Release app configuration
#   --fake      launch on the synthetic --fake findings (MACAUDIT_FAKE=1)
#   --no-open   build only
#   --no-ffi    skip scripts/build-ffi.sh (no Rust changes since last run)
set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG=Debug
FFI_FLAGS=(--debug)
FAKE=0
OPEN=1
FFI=1
for arg in "$@"; do
  case "$arg" in
    --release) CONFIG=Release; FFI_FLAGS=(--release) ;;
    --fake) FAKE=1 ;;
    --no-open) OPEN=0 ;;
    --no-ffi) FFI=0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# Pin the arch so xcodebuild doesn't warn about "multiple matching destinations".
case "$(uname -m)" in arm64) ARCH=arm64 ;; *) ARCH=x86_64 ;; esac
DERIVED=build/DerivedData
APP="$DERIVED/Build/Products/$CONFIG/MacAudit.app"

if [[ $FFI -eq 1 ]]; then
  echo "== engine + bindings (${FFI_FLAGS[*]})"
  scripts/build-ffi.sh "${FFI_FLAGS[@]}"
fi

echo "== xcodegen"
xcodegen generate --spec apps/MacAudit/project.yml --quiet

echo "== xcodebuild ($CONFIG)"
xcodebuild -project apps/MacAudit/MacAudit.xcodeproj -scheme MacAudit \
  -configuration "$CONFIG" -destination "platform=macOS,arch=$ARCH" \
  -derivedDataPath "$DERIVED" -quiet build

echo "== $APP"
codesign -dvv "$APP" 2>&1 | grep -E '^(Authority|TeamIdentifier)=' | head -2 || true

if [[ $OPEN -eq 1 ]]; then
  # `open` does not pass this shell's environment to the app; `--env` does.
  if [[ $FAKE -eq 1 ]]; then
    open --env MACAUDIT_FAKE=1 "$APP"
  else
    open "$APP"
  fi
fi
