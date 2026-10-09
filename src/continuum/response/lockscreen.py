"""Workstation locking.

Responsibility: call user32!LockWorkStation via ctypes to lock the active
session when detection confirms an injection attack. Contains no device
logic; device disable/enable lives in blocker_windows.py.
"""
