#!/usr/bin/env bash
# Build the Rust engine as a static library and generate the Swift bindings
# the app consumes: swift/MacAuditKit/MacAuditFFI.xcframework plus
# swift/MacAuditKit/Sources/MacAuditKit/Generated/macaudit.swift.
#
# The .a and the .swift must always come from the same build — the generated
# Swift carries per-symbol checksums that the library verifies at load — so
# this script always regenerates both, and both are gitignored.
#
#   scripts/build-ffi.sh [--release|--debug] [--universal]
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)

PROFILE=debug
CARGO_PROFILE_FLAG=()
TARGETS=(aarch64-apple-darwin)
for arg in "$@"; do
  case "$arg" in
    --release) PROFILE=release; CARGO_PROFILE_FLAG=(--release) ;;
    --debug) PROFILE=debug; CARGO_PROFILE_FLAG=() ;;
    --universal) TARGETS=(aarch64-apple-darwin x86_64-apple-darwin) ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

OUT="$ROOT/build/ffi"
KIT="$ROOT/swift/MacAuditKit"
GEN="$KIT/Sources/MacAuditKit/Generated"
XCF="$KIT/MacAuditFFI.xcframework"
LIB_NAME=libmacaudit_ffi.a

# Match the app's deployment target so C objects (aws-lc via reqwest/rustls)
# don't link with "built for newer macOS" warnings.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
TARGET_DIR=$(cargo devtools target-directory)
for target in "${TARGETS[@]}"; do
  target_lib=$(rustc --print target-libdir --target "$target")
  for stdlib in "$target_lib"/libstd-*.rlib; do
    if [ ! -f "$stdlib" ]; then
      echo "Rust standard library unavailable for $target" >&2
      exit 1
    fi
    if ! otool -l "$stdlib" | awk -v target="$MACOSX_DEPLOYMENT_TARGET" '
      BEGIN { split(target, minimum, ".") }
      $1 == "minos" {
        split($2, actual, ".")
        if (actual[1] > minimum[1] || (actual[1] == minimum[1] && actual[2] > minimum[2])) incompatible = 1
      }
      END { exit incompatible }
    '; then
      echo "Rust standard library for $target requires newer macOS than $MACOSX_DEPLOYMENT_TARGET; use an official Rust toolchain with compatible deployment support." >&2
      exit 1
    fi
  done
done

rm -rf "$OUT"
mkdir -p "$OUT/Headers" "$OUT/swift" "$GEN"

LIBS=()
for target in "${TARGETS[@]}"; do
  echo "== cargo build ($PROFILE, $target)"
  cargo build --locked -p macaudit-ffi --target "$target" ${CARGO_PROFILE_FLAG[@]+"${CARGO_PROFILE_FLAG[@]}"}
  LIBS+=("$TARGET_DIR/$target/$PROFILE/$LIB_NAME")
done

if [ "${#LIBS[@]}" -gt 1 ]; then
  echo "== lipo"
  lipo -create "${LIBS[@]}" -output "$OUT/$LIB_NAME"
  LIB="$OUT/$LIB_NAME"
else
  LIB="${LIBS[0]}"
fi

BINDGEN=(cargo run -q -p uniffi-bindgen --bin uniffi-bindgen-swift --)
echo "== uniffi-bindgen-swift"
"${BINDGEN[@]}" --swift-sources "$LIB" "$OUT/swift"
"${BINDGEN[@]}" --headers "$LIB" "$OUT/Headers"
# The frameworks the Rust static library needs at final link. Link
# directives from build scripts (security-framework, objc2) do not survive
# into a .a, so they are declared here and in Package.swift (which also
# adds -liconv and -lobjc); confirm the list with
#   cargo rustc -p macaudit-ffi --target aarch64-apple-darwin -- --print native-static-libs
"${BINDGEN[@]}" --modulemap --module-name MacAuditFFI --modulemap-filename module.modulemap \
  --link-frameworks Security --link-frameworks CoreFoundation --link-frameworks Foundation \
  "$LIB" "$OUT/Headers"

echo "== xcframework"
rm -rf "$XCF"
xcodebuild -quiet -create-xcframework -library "$LIB" -headers "$OUT/Headers" -output "$XCF"

echo "== swift sources"
rm -f "$GEN"/*.swift
cp "$OUT"/swift/*.swift "$GEN/"

echo "done: $XCF"
echo "      $GEN/$(ls "$GEN" | head -1)"
