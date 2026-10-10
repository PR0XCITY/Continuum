"""Workstation locking.

Responsibility: call user32!LockWorkStation via ctypes to lock the
active session the moment detection confirms an injection attack.

Speed matters here more than anywhere else in Continuum. This must run
before anything else in the response pipeline, including building or
sending an incident record: an injected payload can act in
milliseconds, and once the session is locked, anything it still sends
goes to the lock screen's password box, not to a terminal or the Run
dialog. Contains no device logic; device disable/enable lives in
blocker_windows.py.

Importable on any platform; lock_workstation() simply returns False off
Windows instead of raising, so the rest of response stays testable
anywhere.
"""

from __future__ import annotations

import ctypes
import sys

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _user32.LockWorkStation.argtypes = []
    _user32.LockWorkStation.restype = ctypes.c_int
else:
    _user32 = None


def lock_workstation() -> bool:
    """Lock the active session. Returns True on success, never raises.

    Safe to call even if the session is already locked (Windows just
    no-ops). A failure here must not stop the rest of the response
    pipeline; disabling the offending device still matters even if the
    lock call itself somehow failed.
    """
    if not IS_WINDOWS or _user32 is None:
        return False
    try:
        result = _user32.LockWorkStation()
    except OSError:
        return False
    return bool(result)
