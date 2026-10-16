"""Remote-access tools: which are running, and ending their sessions.

Responsibility: list the names of running processes through the Toolhelp
API (ctypes, kernel32), match them against the configured remote-access
tool names, and, when the response says so, end those processes with
taskkill. Only process names that match the configured list ever leave
this module; nothing else about running programs is recorded.

Importable on any platform; off Windows no process is reported running
and nothing is ended, so the rest of Continuum stays testable anywhere.
"""

from __future__ import annotations

import ctypes
import logging
import subprocess
import sys
from collections.abc import Callable, Iterable
from ctypes import wintypes

IS_WINDOWS = sys.platform == "win32"

_logger = logging.getLogger(__name__)

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260
TASKKILL_TIMEOUT_SECONDS = 10


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * MAX_PATH),
    ]


if IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
else:
    _kernel32 = None


def list_process_names() -> list[str]:
    """The executable name of every running process. Empty off Windows or on failure."""
    if not IS_WINDOWS or _kernel32 is None:
        return []
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        _logger.debug("could not snapshot running processes")
        return []
    names: list[str] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        more = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            names.append(entry.szExeFile)
            more = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snapshot)
    return names


def running_remote_tools(
    tools: Iterable[str],
    *,
    list_processes: Callable[[], list[str]] = list_process_names,
) -> list[str]:
    """The configured tool names that are running now, as configured, sorted."""
    wanted = {tool.lower(): tool for tool in tools}
    running = {name.lower() for name in list_processes()}
    return sorted(wanted[name] for name in wanted.keys() & running)


def _taskkill(image_name: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["taskkill", "/F", "/T", "/IM", image_name],
            capture_output=True,
            text=True,
            timeout=TASKKILL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _logger.warning("could not run taskkill for %s", image_name, exc_info=True)
        return None


def end_remote_sessions(
    tools: Iterable[str],
    *,
    kill: Callable[[str], subprocess.CompletedProcess | None] = _taskkill,
) -> list[str]:
    """End every process of the given tools. Returns the tool names actually ended.

    Ending the process cuts the remote session. Tools installed as a
    service may start again on their own afterwards, which is fine: the
    session that was typing is gone, and the workstation is locked.
    """
    if not IS_WINDOWS:
        return []
    ended = []
    for tool in tools:
        result = kill(tool)
        if result is not None and result.returncode == 0:
            ended.append(tool)
            _logger.warning("ended remote-access tool %s", tool)
        elif result is not None:
            _logger.warning(
                "taskkill %s failed (exit %s): %s",
                tool,
                result.returncode,
                (result.stderr or result.stdout or "").strip(),
            )
    return ended
