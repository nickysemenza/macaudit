#!/bin/sh
#
# Raises CFBundleShortVersionString in the built Info.plist to the nearest git
# tag. Runs as the app target's "Embed git version" post-build phase (see
# apps/MacAudit/project.yml), before code signing seals the bundle.
#
# The checked-in MARKETING_VERSION is a 0.0.0 floor, not a number to remember
# to bump: the tag is the single source of truth, the same way build.rs stamps
# the CLI. The value is raised to the tag, never lowered, so an explicit
# MARKETING_VERSION= on the xcodebuild line (what scripts/package.sh passes)
# still wins whenever it is ahead of the last tag — package.sh 0.2.0 builds an
# honest 0.2.0 before v0.2.0 exists.
#
# Best-effort throughout: never fail a build over version metadata. With no
# git or no tags (a shallow CI checkout), whatever the project set stands.
#
# This phase is why ENABLE_USER_SCRIPT_SANDBOXING must stay NO in project.yml:
# the script shells out to git and writes into the already-built Info.plist,
# both outside what the user-script sandbox allows.
set -e

plist="${TARGET_BUILD_DIR}/${INFOPLIST_PATH}"
if [ ! -f "$plist" ]; then
    echo "warning: Embed git version: Info.plist not found at $plist"
    exit 0
fi

# SRCROOT is apps/MacAudit; the repo root is two levels up.
cd "${SRCROOT}/../.."

tag=$(git describe --tags --abbrev=0 2>/dev/null || true)
version=${tag#v}

# Only a clean dotted-numeric core is a release version; anything else
# ("nightly", a bare integer) leaves the project's value alone.
case "$version" in
    '' | *[!0-9.]* | *..* | .* | *.) exit 0 ;;
    *.*) ;;
    *) exit 0 ;;
esac

current=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist" 2>/dev/null || true)
highest=$(printf '%s\n%s\n' "$current" "$version" | sort -V | tail -n 1)
if [ "$highest" = "$version" ]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$plist"
fi
