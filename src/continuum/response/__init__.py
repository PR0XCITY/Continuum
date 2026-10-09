"""Response actions taken when detection flags an injection attack.

Responsibility: lock the workstation, disable the offending HID device via
pnputil, raise an operator-visible alert, and enforce the safety rails that
keep this project from locking a user out of their own machine.

Modules:
    blocker_windows.py  Device disable/enable via pnputil, allowlist
                         checks, "never block the last keyboard" and
                         "never block an allowlisted device" enforcement,
                         auto-release after a configurable timeout, and a
                         single release-everything escape hatch.
    lockscreen.py       Workstation locking via user32 LockWorkStation.
    alerts.py           Toast notifications via PowerShell or winotify.

Every function here that disables a device must go through
blocker_windows.py's safety checks; nothing else in this package may call
pnputil directly.
"""
