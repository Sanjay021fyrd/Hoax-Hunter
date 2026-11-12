"""One-command launcher for Hoax Hunter. Works on Windows, macOS and Linux.

    python run.py          (on Windows you can also use:  py run.py)

First run: creates a private virtual environment (.venv), installs the
requirements and starts the app. Later runs just start the app.

Optional environment variables:
    PORT=8080        use another port (default 8501)
    NO_BROWSER=1     do not open the browser automatically
"""

import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
INSTALLED_MARKER = VENV_DIR / ".requirements-installed"
MIN_PYTHON = (3, 10)
PORT = int(os.environ.get("PORT", "8501"))


def venv_python() -> Path:
    sub = "Scripts/python.exe" if os.name == "nt" else "bin/python"
    return VENV_DIR / sub


def venv_works() -> bool:
    """A .venv copied from another computer exists but does not run."""
    try:
        return (
            subprocess.run(
                [str(venv_python()), "-c", "import sys"], capture_output=True
            ).returncode
            == 0
        )
    except OSError:
        return False


def ensure_environment() -> Path:
    if not venv_works():
        print("Creating virtual environment (first run only)...")
        venv.EnvBuilder(with_pip=True, clear=True).create(VENV_DIR)
    python = venv_python()

    up_to_date = (
        INSTALLED_MARKER.exists()
        and INSTALLED_MARKER.stat().st_mtime >= REQUIREMENTS.stat().st_mtime
    )
    if not up_to_date:
        print("Installing requirements (first run only, ~1-2 minutes)...")
        subprocess.check_call(
            [str(python), "-m", "pip", "install", "--quiet", "-r", str(REQUIREMENTS)]
        )
        INSTALLED_MARKER.touch()
    return python


def open_browser_when_ready() -> None:
    url = f"http://localhost:{PORT}"
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"{url}/_stcore/health", timeout=2):
                webbrowser.open(url)
                return
        except OSError:
            time.sleep(0.5)


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        need = ".".join(map(str, MIN_PYTHON))
        print(
            f"Hoax Hunter needs Python {need} or newer (you have {sys.version.split()[0]})."
        )
        print("Download it from https://www.python.org/downloads/")
        return 1

    python = ensure_environment()
    os.chdir(ROOT)

    if not os.environ.get("NO_BROWSER"):
        threading.Thread(target=open_browser_when_ready, daemon=True).start()

    print(f"Starting Hoax Hunter on http://localhost:{PORT}  (press Ctrl+C to stop)")
    # --server.headless skips Streamlit's first-run email prompt
    server = subprocess.Popen(
        [
            str(python),
            "-m",
            "streamlit",
            "run",
            "app.py",
            "--server.headless",
            "true",
            "--server.port",
            str(PORT),
            "--browser.gatherUsageStats",
            "false",
        ]
    )

    def stop_server(*_):
        server.terminate()

    # If this launcher is stopped (kill, closing the terminal), stop the app too
    signal.signal(signal.SIGTERM, stop_server)
    try:
        return server.wait()
    except KeyboardInterrupt:  # Ctrl+C
        server.terminate()
        return server.wait()


if __name__ == "__main__":
    sys.exit(main())
