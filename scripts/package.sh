#!/usr/bin/env bash
# Build and sign everything a release ships, into one staging directory:
#
#   <staging-dir>/MacAudit.app   Release app, Developer ID signed
#   <staging-dir>/macaudit       CLI, Developer ID signed, hardened runtime
#
# The Homebrew cask (nickysemenza/homebrew-tap, Casks/macaudit.rb) installs
# both from the zip that scripts/notarize.sh makes of this directory, so
# their names and the flat layout are part of the release contract.
#
#   scripts/package.sh <version> <staging-dir>
#
# Env:
#   SIGN_IDENTITY   codesign identity (default "Developer ID Application";
#                   "-" ad-hoc signs, for a build on a machine without the
#                   certificate — such a build cannot be notarized)
#   BUILD_NUMBER    CFBundleVersion (default 1; release.yml passes the run number)
#
# arm64 only: the cask declares `depends_on arch: :arm64`, so there is no
# lipo step here and the app is built with ARCHS=arm64 (the xcframework
# from build-ffi.sh carries a single arm64 slice, which a default Release
# build would fail to link for x86_64).
set -euo pipefail

VERSION=${1:?usage: scripts/package.sh <version> <staging-dir>}
STAGE=${2:?usage: scripts/package.sh <version> <staging-dir>}
SIGN_IDENTITY=${SIGN_IDENTITY:-Developer ID Application}
BUILD_NUMBER=${BUILD_NUMBER:-1}
TEAM=Y9A97FXT63
TARGET=aarch64-apple-darwin

cd "$(dirname "$0")/.."
ROOT=$(pwd)
case "$STAGE" in /*) ;; *) STAGE="$ROOT/$STAGE" ;; esac

# The tag is the only version source: build.rs bakes MACAUDIT_VERSION into
# `macaudit --version` and the User-Agent, and the xcodebuild line below
# passes the same value as MARKETING_VERSION. Verified after the build.
export MACAUDIT_VERSION="$VERSION"

# Same floor as the app so the CLI runs on the same macOS versions.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"

echo "== cargo build (release, $TARGET)"
cargo build --release --locked -p macaudit --target "$TARGET"
CLI="$ROOT/target/$TARGET/release/macaudit"

echo "== engine static library + Swift bindings"
scripts/build-ffi.sh --release

echo "== xcodegen"
xcodegen generate --spec apps/MacAudit/project.yml

echo "== xcodebuild (Release, signed: $SIGN_IDENTITY)"
# CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO: `xcodebuild build` (unlike
# `archive`) injects com.apple.security.get-task-allow into the signature,
# which the notary service rejects outright. Distribution builds must not
# carry it. DEVELOPMENT_TEAM is stated because the Developer ID identity
# lookup is keyed on it; an ad-hoc identity has no team.
XCODE_SIGN_ARGS=(CODE_SIGN_STYLE=Manual "CODE_SIGN_IDENTITY=$SIGN_IDENTITY")
if [ "$SIGN_IDENTITY" = "-" ]; then
  XCODE_SIGN_ARGS+=(DEVELOPMENT_TEAM=)
else
  XCODE_SIGN_ARGS+=("DEVELOPMENT_TEAM=$TEAM" "OTHER_CODE_SIGN_FLAGS=--timestamp")
fi
DERIVED="$ROOT/build/DerivedData"
xcodebuild -quiet -project apps/MacAudit/MacAudit.xcodeproj -scheme MacAudit \
  -configuration Release -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath "$DERIVED" ARCHS=arm64 \
  "${XCODE_SIGN_ARGS[@]}" CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  "MARKETING_VERSION=$VERSION" "CURRENT_PROJECT_VERSION=$BUILD_NUMBER" \
  build
APP="$DERIVED/Build/Products/Release/MacAudit.app"

echo "== stage $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/MacAudit.app"
cp "$CLI" "$STAGE/macaudit"

echo "== codesign macaudit"
# The hardened runtime and a secure timestamp are what notarization checks
# for on a bare executable; cargo's output only carries the linker's ad-hoc
# signature.
CODESIGN_ARGS=(--force --options runtime --sign "$SIGN_IDENTITY")
[ "$SIGN_IDENTITY" != "-" ] && CODESIGN_ARGS+=(--timestamp)
codesign "${CODESIGN_ARGS[@]}" "$STAGE/macaudit"

echo "== verify"
codesign --verify --deep --strict "$STAGE/MacAudit.app"
codesign --verify --strict "$STAGE/macaudit"
GOT=$("$STAGE/macaudit" --version)
if [ "$GOT" != "macaudit $VERSION" ]; then
  echo "error: built CLI reports '$GOT', expected 'macaudit $VERSION'" >&2
  exit 1
fi
PLIST_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$STAGE/MacAudit.app/Contents/Info.plist")
if [ "$PLIST_VERSION" != "$VERSION" ]; then
  echo "error: app bundle reports version '$PLIST_VERSION', expected '$VERSION'" >&2
  exit 1
fi
echo "done: $STAGE/MacAudit.app ($PLIST_VERSION, build $BUILD_NUMBER)"
echo "      $STAGE/macaudit ($GOT)"
