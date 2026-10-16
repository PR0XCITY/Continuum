"""Starting and stopping Continuum's background parts from the desktop app.

Responsibility: what `.\\tasks.ps1 run-all`, `stop-all` and `release-all`
do, for an app with no console. The connector API is started hidden as a
child process, logging to data/logs/api.log. The HID Firewall runtime
needs Administrator, so it is started through the Windows elevation
prompt (ShellExecuteEx with the "runas" verb) running the same
`tasks.ps1 window-runtime` target run-all uses. Both write the pid files
in data/run that `tasks.ps1 status` and `stop-all` read, so the app and
the scripts can be mixed freely.
"""

from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from continuum.common.config import Settings

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_DIR = REPO_ROOT / "data" / "run"
LOG_DIR = REPO_ROOT / "data" / "logs"
STOP_REQUEST_PATH = RUN_DIR / "runtime.stop"
TASKS_SCRIPT = REPO_ROOT / "tasks.ps1"

IS_WINDOWS = sys.platform == "win32"
CREATE_NO_WINDOW = 0x08000000
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_SHOWMINNOACTIVE = 7
SW_SHOWNORMAL = 1
ERROR_CANCELLED = 1223


def _python_executable() -> str:
    """The console python.exe next to this interpreter (pythonw.exe has no stdio)."""
    executable = Path(sys.executable)
    console = executable.with_name("python.exe")
    return str(console if console.exists() else executable)


def _pid_alive(pid: int) -> bool:
    if not IS_WINDOWS:
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def component_running(name: str) -> bool:
    """True if data/run/<name>.pid names a live process, as tasks.ps1 status checks."""
    try:
        pid = int((RUN_DIR / f"{name}.pid").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return False
    return _pid_alive(pid)


def _write_pid(name: str, pid: int) -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    (RUN_DIR / f"{name}.pid").write_text(str(pid), encoding="ascii")


def start_api(settings: Settings) -> subprocess.Popen | None:
    """Start the connector API hidden, unless it is already running."""
    if component_running("api"):
        return None
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log = open(LOG_DIR / "api.log", "a", encoding="utf-8")  # noqa: SIM115 - owned by the child
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    process = subprocess.Popen(
        [
            _python_executable(),
            "-m",
            "uvicorn",
            "continuum.connector.app:app",
            "--host",
            settings.connector.host,
            "--port",
            str(settings.connector.port),
        ],
        cwd=REPO_ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=env,
        creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0,
    )
    _write_pid("api", process.pid)
    logger.info("started the connector API (pid %d)", process.pid)
    return process


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def _run_elevated(target: str, *, show: int, keep_open: bool) -> int | None:
    """Run a tasks.ps1 target as Administrator. Returns the pid, or None if declined."""
    if not IS_WINDOWS:
        return None
    no_exit = "-NoExit " if keep_open else ""
    parameters = (
        f'{no_exit}-NoProfile -ExecutionPolicy Bypass -File "{TASKS_SCRIPT}" {target}'
    )
    info = _ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = "powershell.exe"
    info.lpParameters = parameters
    info.lpDirectory = str(REPO_ROOT)
    info.nShow = show
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == ERROR_CANCELLED:
            logger.info("elevation prompt declined for %s", target)
        else:
            logger.warning("could not start %s elevated (error %d)", target, error)
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pid = kernel32.GetProcessId(info.hProcess)
    kernel32.CloseHandle(info.hProcess)
    return pid


def start_runtime() -> bool:
    """Start the HID Firewall runtime elevated, minimised. False if declined."""
    if component_running("runtime"):
        return True
    pid = _run_elevated("window-runtime", show=SW_SHOWMINNOACTIVE, keep_open=True)
    if pid is None:
        return False
    _write_pid("runtime", pid)
    return True


def request_runtime_stop() -> None:
    """Ask the runtime to stop cleanly; it releases every blocked device first."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    STOP_REQUEST_PATH.write_text("", encoding="ascii")


def release_all_devices() -> bool:
    """Run the kill switch elevated, in a visible window that shows the result."""
    return _run_elevated("release-all", show=SW_SHOWNORMAL, keep_open=True) is not None


def stop_api(process: subprocess.Popen | None) -> None:
    """Stop the API, but only one this app started itself."""
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    (RUN_DIR / "api.pid").unlink(missing_ok=True)
