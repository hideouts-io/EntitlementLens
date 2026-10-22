#!/usr/bin/env bash
set -euo pipefail

APP_NAME="EntitlementLens"
BUNDLE_ID="io.hideouts.EntitlementLens"
MIN_SYSTEM_VERSION="14.0"
CODESIGN_IDENTITY="${ENTITLEMENTLENS_CODESIGN_IDENTITY:--}"

ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_ICON_SOURCE="$ROOT_DIR/Assets/Brand/Lens-v4/EntitlementLens-AppIcon-Dark-1024.png"
APP_ICON_NAME="$APP_NAME.icns"
APP_ICON="$APP_RESOURCES/$APP_ICON_NAME"
APP_LAUNCH_DAEMONS="$APP_CONTENTS/Library/LaunchDaemons"
HELPER_NAME="EntitlementLensPrivilegedHelper"
HELPER_BINARY="$APP_RESOURCES/$HELPER_NAME"
HELPER_PLIST_NAME="io.hideouts.EntitlementLens.PrivilegedHelper.plist"
HELPER_PLIST="$APP_LAUNCH_DAEMONS/$HELPER_PLIST_NAME"

read_snapshot() {
  local result
  if ! result="$(/usr/bin/swift "$ROOT_DIR/script/collector_build_snapshot.swift" "$ROOT_DIR")"; then
    echo "warning: collector build provenance is unknown: the Git snapshot tool failed" >&2
    printf 'unknown\n'
    return
  fi
  if [[ "$result" == "unknown" || "$result" =~ ^(clean|dirty)\|[0-9a-f]{40}\|[0-9a-f]{64}$ ]]; then
    printf '%s\n' "$result"
  else
    echo "warning: collector build provenance is unknown: the Git snapshot response was invalid" >&2
    printf 'unknown\n'
  fi
}

if [[ ! -f "$APP_ICON_SOURCE" ]]; then
  echo "missing application icon: $APP_ICON_SOURCE" >&2
  exit 1
fi

SNAPSHOT_BEFORE="$(read_snapshot)"
swift build --package-path "$ROOT_DIR"
BUILD_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/$APP_NAME"
BUILD_HELPER_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/$HELPER_NAME"

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS" "$APP_RESOURCES" "$APP_LAUNCH_DAEMONS"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$BUILD_HELPER_BINARY" "$HELPER_BINARY"
chmod +x "$APP_BINARY"
chmod +x "$HELPER_BINARY"

ICON_WORK_DIR="$(mktemp -d /tmp/EntitlementLensIcon.XXXXXX)"
ICONSET="$ICON_WORK_DIR/$APP_NAME.iconset"
mkdir -p "$ICONSET"

create_icon_variant() {
  local pixels="$1"
  local filename="$2"
  /usr/bin/sips -z "$pixels" "$pixels" "$APP_ICON_SOURCE" --out "$ICONSET/$filename" >/dev/null
}

create_icon_variant 16 icon_16x16.png
create_icon_variant 32 icon_16x16@2x.png
create_icon_variant 32 icon_32x32.png
create_icon_variant 64 icon_32x32@2x.png
create_icon_variant 128 icon_128x128.png
create_icon_variant 256 icon_128x128@2x.png
create_icon_variant 256 icon_256x256.png
create_icon_variant 512 icon_256x256@2x.png
create_icon_variant 512 icon_512x512.png
create_icon_variant 1024 icon_512x512@2x.png
/usr/bin/iconutil -c icns "$ICONSET" -o "$APP_ICON"
rm -rf "$ICON_WORK_DIR"

SNAPSHOT_AFTER="$(read_snapshot)"
COLLECTOR_BUILD_STATE="dirty"
SOURCE_COMMIT_XML=""
if [[ "$SNAPSHOT_BEFORE" == "unknown" || "$SNAPSHOT_AFTER" == "unknown" ]]; then
  COLLECTOR_BUILD_STATE="unknown"
elif [[ "$SNAPSHOT_BEFORE" == "$SNAPSHOT_AFTER" && "$SNAPSHOT_AFTER" =~ ^clean\|([0-9a-f]{40})\|[0-9a-f]{64}$ ]]; then
  COLLECTOR_BUILD_STATE="clean"
  SOURCE_COMMIT_XML="    <key>source_commit</key>
    <string>${BASH_REMATCH[1]}</string>"
fi

cat >"$INFO_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundleIconFile</key>
  <string>$APP_ICON_NAME</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>$MIN_SYSTEM_VERSION</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>EntitlementLensCollectorBuild</key>
  <dict>
    <key>state</key>
    <string>$COLLECTOR_BUILD_STATE</string>
$SOURCE_COMMIT_XML
  </dict>
</dict>
</plist>
PLIST

cat >"$HELPER_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.hideouts.EntitlementLens.PrivilegedHelper</string>
  <key>AssociatedBundleIdentifiers</key>
  <array>
    <string>$BUNDLE_ID</string>
  </array>
  <key>BundleProgram</key>
  <string>Contents/Resources/$HELPER_NAME</string>
  <key>MachServices</key>
  <dict>
    <key>io.hideouts.EntitlementLens.PrivilegedHelper</key>
    <true/>
  </dict>
</dict>
</plist>
PLIST

/usr/bin/plutil -lint "$INFO_PLIST" "$HELPER_PLIST"

sign_item() {
  local identifier="$1"
  local path="$2"
  if [[ "$CODESIGN_IDENTITY" == "-" ]]; then
    /usr/bin/codesign \
      --force \
      --sign "$CODESIGN_IDENTITY" \
      --identifier "$identifier" \
      --timestamp=none \
      "$path"
  else
    /usr/bin/codesign \
      --force \
      --sign "$CODESIGN_IDENTITY" \
      --identifier "$identifier" \
      --options runtime \
      --timestamp \
      "$path"
  fi
}

sign_item "io.hideouts.EntitlementLens.PrivilegedHelper" "$HELPER_BINARY"
sign_item "$BUNDLE_ID" "$APP_BUNDLE"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
