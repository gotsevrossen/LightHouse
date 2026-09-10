"""Desktop entry point: the front door for the installed Linux application.

Replaces "run uvicorn, then open a browser to localhost:8000" with a double-click.
Two situations have to work:

* Installed. The systemd unit is already serving the API, and monitoring has been
  running since boot whether or not anybody opened this window. This process only
  opens a window onto it, and closing the window stops nothing.
* From source. Nothing is running yet, so this process starts the API itself, in
  a background thread, and shuts it down when the window closes.

The health probe is what tells the two apart.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen

# Being this entry point is what makes the process the desktop application, so it
# declares that here rather than relying on the launcher to pass an environment
# variable. A frozen build is desktop mode on its own; this covers running from
# source. It must happen before triage.api is imported, because that module opens
# the database at import time and the database path depends on this.
os.environ.setdefault("LIGHTHOUSE_DESKTOP", "1")

from .paths import first_run_password_path  # noqa: E402  (must follow the flag above)

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = int(os.getenv("LIGHTHOUSE_PORT", "8000"))
BASE_URL = f"http://{HOST}:{PORT}"
HEALTH_URL = f"{BASE_URL}/api/health"

# How long to wait for a server this process just started. Cold start includes
# opening the database and running migrations, so it is not instant.
STARTUP_TIMEOUT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.25
WINDOW_TITLE = "LightHouse"


def api_is_up(timeout: float = 0.5) -> bool:
    """True when something is already answering the health endpoint on loopback."""
    try:
        with urlopen(HEALTH_URL, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (URLError, OSError):
        return False


def _serve_forever() -> None:
    """Run uvicorn in-process. Never with reload or LIGHTHOUSE_DEV.

    Both are development-only: reload doubles the process count and re-executes
    application code on any file change, and LIGHTHOUSE_DEV publishes the schema
    and the route table. The desktop build behaves like production always.
    """
    import uvicorn

    from .api import app

    config = uvicorn.Config(app, host=HOST, port=PORT, log_level="info", access_log=False)
    uvicorn.Server(config).run()


def start_api() -> threading.Thread:
    """Start the API on a daemon thread and return once it answers.

    Daemon so that closing the window ends the process rather than leaving a
    headless server behind with no way for the owner to notice or stop it.
    """
    thread = threading.Thread(target=_serve_forever, name="lighthouse-api", daemon=True)
    thread.start()
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if api_is_up():
            return thread
        if not thread.is_alive():
            raise RuntimeError("The LightHouse service stopped while starting up.")
        time.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"The LightHouse service did not start within {STARTUP_TIMEOUT_SECONDS:.0f} seconds.")


def take_first_run_password() -> str | None:
    """Read and delete the one-time admin password, if this is a first run.

    Read-then-delete, so it is shown exactly once no matter how the window is
    closed, matching the guarantee the stdout banner already makes.
    """
    path = first_run_password_path()
    try:
        password = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        path.unlink()
    except OSError:
        logger.warning("Could not remove %s; delete it by hand.", path)
    return password or None


def first_run_message(password: str) -> str:
    return (
        "LightHouse has created your administrator account.\n\n"
        f"    Username:  admin\n"
        f"    Password:  {password}\n\n"
        "Write this down now — it is shown only once.\n\n"
        "Sign in with it and LightHouse will ask you to choose your own "
        "password straight away."
    )


def run_headless() -> int:
    """Serve the API and ingestion with no window, for the systemd unit.

    This is the half of the application that must not depend on anybody being
    logged in: it starts at boot and keeps monitoring whether or not the window is
    ever opened. Same process and same entry point as the window, so there is one
    binary to install and one unit to supervise.
    """
    logger.info("Starting LightHouse monitoring on %s (no window).", BASE_URL)
    _serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    arguments = sys.argv[1:] if argv is None else argv
    if "--headless" in arguments:
        return run_headless()

    import webview

    started_here = False
    if not api_is_up():
        # Nothing is serving: either running from source, or the background
        # service is not installed or has failed. Serve it ourselves.
        logger.info("No LightHouse service answering on %s; starting one.", BASE_URL)
        try:
            start_api()
        except RuntimeError as error:
            webview.create_window(WINDOW_TITLE, html=f"<h1>LightHouse could not start</h1><p>{error}</p>", width=520, height=260)
            webview.start()
            return 1
        started_here = True
    else:
        logger.info("Using the LightHouse service already running on %s.", BASE_URL)

    # Read the password before the window opens: the file only exists on the run
    # that created the account, and that run may have been the background service
    # at boot rather than this process.
    password = take_first_run_password()

    window = webview.create_window(WINDOW_TITLE, BASE_URL, width=1280, height=860, min_size=(960, 640))
    if password:
        # A modal dialog rather than a redesigned onboarding screen: the owner has
        # no terminal and no journal to read this out of, and this is the whole of
        # what they need before the login form is usable.
        def announce() -> None:
            window.create_confirmation_dialog("Your LightHouse password", first_run_message(password))

        webview.start(announce, window)
    else:
        webview.start()

    if started_here:
        logger.info("Window closed; the LightHouse service started by this window is stopping.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
