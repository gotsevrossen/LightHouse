#!/usr/bin/env bash
#
# Build the LightHouse .deb. Run from the repository root on Ubuntu 22.04:
#
#     ./packaging/build-deb.sh
#
# 22.04 and not 24.04, and not a container with a newer base: the binary links
# against the build machine's glibc, and a 22.04 binary runs on 24.04 while the
# reverse fails at startup with an error no owner could act on.

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
ARCH="amd64"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build"
STAGE="${BUILD}/lighthouse_${VERSION}_${ARCH}"

cd "$ROOT"

echo "==> Building the dashboard"
# npm ci, never npm install: it installs exactly the reviewed lockfile tree and
# nothing newer. This output is about to be embedded in a package that installs
# with root privileges on somebody else's machine.
( cd dashboard && npm ci && npm run build )
[ -d dashboard/dist ] || { echo "dashboard/dist was not produced" >&2; exit 1; }

echo "==> Bundling the application"
rm -rf "${ROOT}/dist" "${ROOT}/build/pyinstaller"
python3 -m PyInstaller --clean --noconfirm \
    --distpath "${ROOT}/dist" --workpath "${ROOT}/build/pyinstaller" \
    packaging/lighthouse.spec

echo "==> Staging the package tree"
rm -rf "$STAGE"
install -d "${STAGE}/DEBIAN" \
           "${STAGE}/usr/lib/lighthouse" \
           "${STAGE}/usr/share/applications" \
           "${STAGE}/usr/share/icons/hicolor/256x256/apps" \
           "${STAGE}/usr/share/doc/lighthouse" \
           "${STAGE}/lib/systemd/system"

cp -a "${ROOT}/dist/lighthouse/." "${STAGE}/usr/lib/lighthouse/"
install -m 0755 packaging/install-monitoring-stack.sh "${STAGE}/usr/lib/lighthouse/"
install -m 0644 packaging/systemd/lighthouse.service  "${STAGE}/lib/systemd/system/"
install -m 0644 packaging/desktop/lighthouse.desktop  "${STAGE}/usr/share/applications/"
install -m 0644 assets/lighthouse-logo.png            "${STAGE}/usr/share/icons/hicolor/256x256/apps/lighthouse.png"
install -m 0644 README.md                             "${STAGE}/usr/share/doc/lighthouse/"

# control gets the version and the computed installed size appended; the rest of
# it (dependencies, description) is the reviewed file in debian/.
INSTALLED_KB="$(du -sk "$STAGE" | cut -f1)"

python3 - "$STAGE" "$VERSION" "$ARCH" "$INSTALLED_KB" <<'PY'
import re
import sys

stage, version, arch, size = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open("debian/control", encoding="utf-8") as handle:
    text = handle.read()
# The binary package stanza is everything from "Package:" onward; the source
# stanza above it has no meaning in a built .deb's control file.
binary = text[text.index("Package:"):]
binary = binary.replace("Architecture: amd64", f"Architecture: {arch}", 1)
lines = binary.splitlines()
insert_at = next(i for i, line in enumerate(lines) if line.startswith("Architecture:")) + 1
lines[insert_at:insert_at] = [f"Version: {version}", f"Installed-Size: {size}"]
# Comment lines are for the reader of debian/control, not for dpkg.
body = "\n".join(line for line in lines if not line.startswith("#")) + "\n"
with open(f"{stage}/DEBIAN/control", "w", encoding="utf-8") as handle:
    handle.write(body)
PY

for script in postinst prerm postrm; do
    install -m 0755 "debian/${script}" "${STAGE}/DEBIAN/${script}"
done

echo "==> Building the .deb"
# root:root ownership regardless of who runs the build.
dpkg-deb --root-owner-group --build "$STAGE" "${BUILD}/lighthouse_${VERSION}_${ARCH}.deb"

echo
echo "Built ${BUILD}/lighthouse_${VERSION}_${ARCH}.deb"
echo "Install with: sudo apt install ${BUILD}/lighthouse_${VERSION}_${ARCH}.deb"
