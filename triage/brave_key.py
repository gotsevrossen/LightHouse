"""The Brave Search API key, for web search in chat (`python -m triage.brave_key`).

Stored exactly like the GenAI Studio key (triage.cloud_key): DPAPI-encrypted, in the
admin-only data folder of the install whose Python runs this, set and cleared only
at the command line by an administrator, never shown, logged or sent to the
dashboard. Its own file and DPAPI entropy, so neither key can be read as the other.
Web search is off until a key is stored; see triage.web_search for what is sent.
"""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import sys

from .cloud_key import _audit, _crypt, clean_key, clear, installed_runtime

KEY_FILE_NAME = "brave-key.bin"
_ENTROPY = b"LightHouse/Brave-Search/v1"


def key_path() -> Path:
    """`LIGHTHOUSE_BRAVE_KEY_FILE`, else beside the GenAI Studio key in the data
    folder of the install this Python runtime belongs to (no ProgramData fallback,
    for the reason given in cloud_key.key_path)."""
    configured = os.getenv("LIGHTHOUSE_BRAVE_KEY_FILE", "").strip()
    if configured:
        return Path(configured)
    return Path(sys.executable).resolve().parent.parent / "data" / "config" / KEY_FILE_NAME


def load(path: Path | None = None) -> str | None:
    """The key, or None when none is set or it cannot be decrypted. Never raises."""
    if sys.platform != "win32":
        return None
    try:
        return clean_key(_crypt((path or key_path()).read_bytes(), protect=False, entropy_bytes=_ENTROPY).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def save(key: str, path: Path | None = None) -> Path:
    path = path or key_path()
    if not path.parent.is_dir():
        raise FileNotFoundError(f"LightHouse's data folder was not found at {path.parent}.")
    temporary = path.with_suffix(".tmp")
    # Written inside the protected folder, so it inherits the admin/SYSTEM-only ACL.
    temporary.write_bytes(_crypt(clean_key(key).encode("utf-8"), protect=True, entropy_bytes=_ENTROPY))
    temporary.replace(path)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triage.brave_key")
    parser.add_argument("command", choices=("set", "status", "clear"))
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        print("The Brave Search key store is Windows-only.", file=sys.stderr)
        return 2
    if args.command != "status" and not (os.getenv("LIGHTHOUSE_BRAVE_KEY_FILE", "").strip() or installed_runtime()):
        # Anywhere else the key could land in a folder other users can read.
        print("Run this with LightHouse's own Python, as administrator:\n"
              '  & "<install folder>\\runtime\\python.exe" -m triage.brave_key ' + args.command, file=sys.stderr)
        return 2
    path = key_path()
    try:
        if args.command == "set":
            saved = save(getpass.getpass("Brave Search API key (input hidden): "), path)
            _audit("brave_key_set")
            print(f"Saved, encrypted, to {saved}. Chat uses web search from the next question about an "
                  "alert; no restart is needed.")
        elif args.command == "clear":
            removed = clear(path)
            if removed:
                _audit("brave_key_cleared")
            print("Removed. Chat no longer searches the web, from the next question; no restart is needed."
                  if removed else "No key was set.")
        else:
            print(f"Brave Search key: {'configured' if load(path) else 'not configured'} ({path})")
    except PermissionError:
        print("Run this from PowerShell opened as administrator.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
