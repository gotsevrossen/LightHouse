# PyInstaller spec for the LightHouse Linux desktop build.
#
#   python -m PyInstaller packaging/lighthouse.spec
#
# Run from the repository root, after `npm ci && npm run build` in dashboard/ —
# dashboard/dist is bundled from disk, not built here. Build on the oldest target
# (Ubuntu 22.04): a binary linked against 22.04's glibc runs on 24.04, not the
# reverse. Python 3.11 is the minimum this backend declares and what 22.04 ships.

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(os.getcwd())
DIST = ROOT / "dashboard" / "dist"

if not DIST.is_dir():
    raise SystemExit(
        f"{DIST} is missing. Run `npm ci && npm run build` in dashboard/ before bundling; "
        "the desktop app serves that directory and is useless without it."
    )

hidden = [
    # uvicorn resolves its protocol and lifespan implementations by string name,
    # so the bundler cannot see these as imports.
    *collect_submodules("uvicorn"),
    # Ingestion runs inside the API process in the desktop build, but the API only
    # imports triage.main lazily, inside the lifespan task.
    "triage.main",
    "triage.ingest",
    "triage.llm",
]

analysis = Analysis(
    ["../triage/desktop.py"],
    pathex=[str(ROOT)],
    binaries=[],
    # Extracted to sys._MEIPASS at runtime, which is why triage.paths.bundle_dir()
    # exists rather than the API defaulting to a working-directory-relative path.
    datas=[(str(DIST), "dashboard/dist")],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    # Never bundled: a development file-watcher and a test framework have no place
    # in a binary installed on a customer machine.
    excludes=["tkinter", "pytest", "watchfiles"],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="lighthouse",
    debug=False,
    strip=False,
    upx=False,
    # No terminal: this is launched from a menu entry. The first-run password
    # reaches the owner through the window, not through stdout.
    console=False,
)

COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="lighthouse",
)
