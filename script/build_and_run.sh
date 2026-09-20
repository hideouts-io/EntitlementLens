#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="EntitlementLens"
BUNDLE_ID="io.hideouts.EntitlementLens"
MIN_SYSTEM_VERSION="14.0"
CODESIGN_IDENTITY="${ENTITLEMENTLENS_CODESIGN_IDENTITY:--}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_BINARY="$APP_MACOS/$APP_NAME"
INFO_PLIST="$APP_CONTENTS/Info.plist"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_ICON_SOURCE="$ROOT_DIR/Assets/EntitlementLensLogo-Circular.png"
APP_ICON_NAME="$APP_NAME.icns"
APP_ICON="$APP_RESOURCES/$APP_ICON_NAME"
APP_LAUNCH_DAEMONS="$APP_CONTENTS/Library/LaunchDaemons"
HELPER_NAME="EntitlementLensPrivilegedHelper"
HELPER_BINARY="$APP_RESOURCES/$HELPER_NAME"
HELPER_PLIST_NAME="io.hideouts.EntitlementLens.PrivilegedHelper.plist"
HELPER_PLIST="$APP_LAUNCH_DAEMONS/$HELPER_PLIST_NAME"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

swift build --package-path "$ROOT_DIR"
BUILD_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/$APP_NAME"
BUILD_HELPER_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/$HELPER_NAME"

if [[ ! -f "$APP_ICON_SOURCE" ]]; then
  echo "missing application icon: $APP_ICON_SOURCE" >&2
  exit 1
fi

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

open_app() {
  /usr/bin/open -n "$APP_BUNDLE"
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    sleep 1
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
