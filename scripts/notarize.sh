#!/usr/bin/env bash
# Notarizes the staging directory scripts/package.sh produced, staples the
# app, and zips the result as the release asset.
#
#   scripts/notarize.sh <staging-dir> <out.zip>
#
# Env: NOTARY_KEY_PATH  NOTARY_KEY_ID  NOTARY_ISSUER_ID  (App Store Connect API key)
#
# One submission covers both executables: the notary service tickets every
# Mach-O in the archive. Only the .app bundle can be stapled; the bare CLI
# binary's ticket is fetched online by Gatekeeper the first time a
# quarantined copy runs, which is the case for a Homebrew cask `binary`.
set -euo pipefail

STAGE=${1:?usage: scripts/notarize.sh <staging-dir> <out.zip>}
OUT_ZIP=${2:?usage: scripts/notarize.sh <staging-dir> <out.zip>}
: "${NOTARY_KEY_PATH:?}" "${NOTARY_KEY_ID:?}" "${NOTARY_ISSUER_ID:?}"
KEY=(--key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID")
APP="$STAGE/MacAudit.app"

# Fail here, in seconds, rather than after a notary round trip.
codesign --verify --deep --strict "$APP"
codesign --verify --strict "$STAGE/macaudit"

TMP=$(mktemp -d -t macaudit-notarize)
trap 'rm -rf "$TMP"' EXIT
# No --keepParent: MacAudit.app and macaudit sit at the zip root, which is
# the layout the cask's `app` and `binary` stanzas name.
ditto -c -k --sequesterRsrc "$STAGE" "$TMP/MacAudit.zip"

# notarytool exits non-zero on rejection; keep going so the log can be fetched.
RESULT=$(xcrun notarytool submit "$TMP/MacAudit.zip" "${KEY[@]}" --wait --timeout 20m --output-format json) || true
echo "$RESULT"
ID=$(jq -r '.id // empty' <<< "$RESULT")
STATUS=$(jq -r '.status // empty' <<< "$RESULT")
if [ "$STATUS" != "Accepted" ]; then
  [ -n "$ID" ] && xcrun notarytool log "$ID" "${KEY[@]}"
  echo "error: notarization status '${STATUS:-unknown}'" >&2
  exit 1
fi

xcrun stapler staple "$APP"
rm -f "$OUT_ZIP"
ditto -c -k --sequesterRsrc "$STAGE" "$OUT_ZIP"
spctl -a -vv -t exec "$APP"
echo "Notarized and stapled: $OUT_ZIP"
