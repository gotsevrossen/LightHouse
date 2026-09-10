#!/usr/bin/env bash
#
# Bootstrap a fresh Ubuntu 22.04 desktop VM into a machine that has LightHouse
# built from source and installed. For development and testing only — customers
# never see this file; they install the .deb this script produces.
#
# On a blank VM:
#
#     curl -fsSL https://raw.githubusercontent.com/gotsevrossen/LightHouse/main/dev/bootstrap-test-vm.sh | bash
#
# Or, from inside an already-cloned checkout:
#
#     ./dev/bootstrap-test-vm.sh
#
# 22.04 and not 24.04: the PyInstaller binary links against the build machine's
# glibc, and a 22.04 build runs on 24.04 while the reverse fails at startup.
#
# Environment overrides:
#   LIGHTHOUSE_REF   git ref to build (default: main)
#   LIGHTHOUSE_DIR   where to clone (default: $HOME/LightHouse)
#   LIGHTHOUSE_REPO  clone URL

set -euo pipefail

REF="${LIGHTHOUSE_REF:-main}"
DIR="${LIGHTHOUSE_DIR:-$HOME/LightHouse}"
REPO="${LIGHTHOUSE_REPO:-https://github.com/gotsevrossen/LightHouse.git}"
VERSION="${VERSION:-0.1.0}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die()  { printf '\n\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight --

[ "$(id -u)" -ne 0 ] || die "Run this as your normal user, not as root. It calls sudo where it needs to, and the build (npm, pip) must not run as root."

command -v sudo >/dev/null || die "sudo is not installed."

if [ -r /etc/os-release ]; then
    . /etc/os-release
    if [ "${VERSION_ID:-}" != "22.04" ]; then
        printf '\033[1;33mWarning: this is %s %s, not Ubuntu 22.04.\033[0m\n' "${NAME:-unknown}" "${VERSION_ID:-?}"
        printf 'A .deb built here will not install on older releases. Continuing in 5s (Ctrl-C to stop).\n'
        sleep 5
    fi
fi

# Prime sudo once so the long unattended stretch below does not stall on a
# password prompt halfway through an apt run.
step "Requesting sudo (you will be asked for your password once)"
sudo -v

# ------------------------------------------------------------ system packages --

step "Installing system packages"
sudo apt-get update
sudo apt-get install -y \
    git curl ca-certificates \
    python3 python3-pip python3-venv python3-dev \
    dpkg-dev build-essential

# Ubuntu 22.04 ships Node 12 in its own repos; the dashboard needs 20+. The
# NodeSource package includes npm, so npm is deliberately not installed from apt.
step "Installing Node.js 20"
if ! node --version 2>/dev/null | grep -qE '^v(2[0-9]|[3-9][0-9])\.'; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
node --version
npm --version

# ------------------------------------------------------------------- source --

if [ -f "packaging/build-deb.sh" ] && [ -d ".git" ]; then
    # Already running from inside a checkout: build this tree as it stands,
    # rather than cloning a second copy somewhere else.
    DIR="$(pwd)"
    step "Building the checkout in $DIR (no clone, no checkout of $REF)"
else
    step "Fetching the source into $DIR"
    if [ -d "$DIR/.git" ]; then
        git -C "$DIR" fetch --all --tags --prune
    else
        git clone "$REPO" "$DIR"
    fi
    git -C "$DIR" checkout "$REF"
    # Fast-forward only when the ref is a branch; a tag or SHA leaves a detached
    # HEAD, where pull is meaningless.
    if git -C "$DIR" symbolic-ref -q HEAD >/dev/null; then
        git -C "$DIR" pull --ff-only
    fi
fi

cd "$DIR"
printf 'Building %s\n' "$(git rev-parse --short HEAD) — $(git log -1 --pretty=%s)"

# -------------------------------------------------------------- python deps --

# A virtualenv rather than a system pip install: 24.04 refuses the latter
# outright (PEP 668), and on 22.04 it keeps PyInstaller and its build deps out
# of the system Python, which the installed .deb does not use anyway.
step "Creating the virtualenv and installing Python dependencies"
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[desktop,dev]'

# --------------------------------------------------------------- build/test --

step "Running the test suite"
pytest -q || die "Tests failed. Fix them before packaging — the .deb would ship the same code."

step "Building the .deb"
./packaging/build-deb.sh

DEB="build/lighthouse_${VERSION}_amd64.deb"
[ -f "$DEB" ] || die "$DEB was not produced."

# ------------------------------------------------------------------ install --

# The postinst does the real work: sensors, Ollama, the model pull, HOME_NET
# detection, the service. It takes a while the first time.
step "Installing $DEB (this pulls the AI model — expect several minutes)"
sudo apt-get install -y "$DIR/$DEB"

# ------------------------------------------------------------------- finish --

cat <<'DONE'

============================================================
 LightHouse is built and installed.

 One manual step remains, and it cannot be automated from
 here: the installer added you to the "lighthouse" group,
 and group membership only takes effect on a new login
 session. Log out and back in, then launch LightHouse from
 the applications menu.

 Check the service in the meantime:
   systemctl status lighthouse
============================================================
DONE
