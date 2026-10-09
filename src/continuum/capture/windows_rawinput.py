"""Windows Raw Input API capture backend.

Responsibility: register for raw keyboard input via the Win32 Raw Input
API (RegisterRawInputDevices / WM_INPUT) through ctypes, resolve each
event to its originating physical device, and push a minimal KeyEvent
(no key identity) onto the capture queue for every down/up transition.

Raw Input is used instead of a global keyboard hook (SetWindowsHookEx)
because a hook receives synthesized input indistinguishably from real
input and cannot tell which physical device produced it. Raw Input
exposes the originating device handle, which is exactly the signal this
project needs to isolate an injection attack to one device and disable
only that device. See docs/windows_notes.md for the full explanation and
known limits.

Key-identity confinement: the only place in this module that ever holds
a VKey value is _PressTracker, used solely to detect OS auto-repeat and
to pair a key-down with its matching key-up. VKey is passed into it as a
transient argument and is never attached to a KeyEvent, never logged,
and never exposed outside that one class; it is discarded whenever
capture stops (_PressTracker.reset()) or a device is removed
(_PressTracker.release_device()).

This module is importable on any platform so the rest of the test suite
can import continuum.capture without a Windows machine; only start()
touches real Win32 state, and it raises immediately on non-Windows.
Capture runs unprivileged: nothing here requires Administrator rights.
"""

from __future__ import annotations

import ctypes
import itertools
import re
import sys
import threading
from ctypes import wintypes
from datetime import UTC, datetime
from typing import Literal

from continuum.capture.base import DEFAULT_PUT_TIMEOUT_SECONDS, DEFAULT_QUEUE_MAXSIZE, CaptureSource
from continuum.common.schemas import DeviceInfo, KeyEvent

IS_WINDOWS = sys.platform == "win32"

# --- Win32 constants -------------------------------------------------------

HWND_MESSAGE = -3

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_INPUT = 0x00FF
WM_INPUT_DEVICE_CHANGE = 0x00FE

GIDC_ARRIVAL = 1
GIDC_REMOVAL = 2

RIDEV_REMOVE = 0x00000001
RIDEV_INPUTSINK = 0x00000100
RIDEV_DEVNOTIFY = 0x00002000

RID_INPUT = 0x10000003
RIDI_DEVICENAME = 0x20000007

RIM_TYPEKEYBOARD = 1

HID_USAGE_PAGE_GENERIC = 0x01
HID_USAGE_GENERIC_KEYBOARD = 0x06

THREAD_PRIORITY_HIGHEST = 2

RI_KEY_BREAK = 0x01

# Sentinel VKey Windows sends as the first half of certain extended-key
# escape sequences. It carries no real key information and must be
# discarded before anything else touches it.
FAKE_VKEY_ESCAPE = 0xFF

ERROR_CLASS_ALREADY_EXISTS = 1410

_DEVICE_PATH_PREFIX = "\\\\?\\"
_VID_PID_PATTERN = re.compile(r"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


# --- ctypes structures -------------------------------------------------------
# These only use plain ctypes primitives and ctypes.wintypes aliases, both
# of which are defined on every platform, so this section never raises on
# import, even off Windows.


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", wintypes.DWORD),
        ("dwSize", wintypes.DWORD),
        ("hDevice", wintypes.HANDLE),
        ("wParam", wintypes.WPARAM),
    ]


class RAWKEYBOARD(ctypes.Structure):
    _fields_ = [
        ("MakeCode", wintypes.USHORT),
        ("Flags", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("VKey", wintypes.USHORT),
        ("Message", wintypes.UINT),
        ("ExtraInformation", wintypes.ULONG),
    ]


class _RAWINPUTDATA(ctypes.Union):
    # We only ever register for keyboard input, so the keyboard member is
    # the only one this project needs to read.
    _fields_ = [("keyboard", RAWKEYBOARD)]


class RAWINPUT(ctypes.Structure):
    _fields_ = [
        ("header", RAWINPUTHEADER),
        ("data", _RAWINPUTDATA),
    ]


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", wintypes.USHORT),
        ("usUsage", wintypes.USHORT),
        ("dwFlags", wintypes.DWORD),
        ("hwndTarget", wintypes.HWND),
    ]


class RAWINPUTDEVICELIST(ctypes.Structure):
    _fields_ = [
        ("hDevice", wintypes.HANDLE),
        ("dwType", wintypes.DWORD),
    ]


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


# --- DLL handles, only resolved on Windows -----------------------------------

if IS_WINDOWS:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(
        LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    )

    def _configure_win32_functions() -> None:
        user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
        user32.RegisterClassExW.restype = wintypes.ATOM

        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HANDLE,
            wintypes.HINSTANCE,
            ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND

        user32.DefWindowProcW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.DefWindowProcW.restype = LRESULT

        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL

        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.PostQuitMessage.restype = None

        user32.PostMessageW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.PostMessageW.restype = wintypes.BOOL

        user32.GetMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.GetMessageW.restype = wintypes.BOOL

        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL

        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = LRESULT

        user32.RegisterRawInputDevices.argtypes = [
            ctypes.POINTER(RAWINPUTDEVICE),
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.RegisterRawInputDevices.restype = wintypes.BOOL

        user32.GetRawInputData.argtypes = [
            wintypes.HANDLE,
            wintypes.UINT,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.UINT),
            wintypes.UINT,
        ]
        user32.GetRawInputData.restype = wintypes.UINT

        user32.GetRawInputDeviceInfoW.argtypes = [
            wintypes.HANDLE,
            wintypes.UINT,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.UINT),
        ]
        user32.GetRawInputDeviceInfoW.restype = wintypes.UINT

        user32.GetRawInputDeviceList.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.UINT),
            wintypes.UINT,
        ]
        user32.GetRawInputDeviceList.restype = wintypes.UINT

        kernel32.GetCurrentThread.argtypes = []
        kernel32.GetCurrentThread.restype = wintypes.HANDLE

        kernel32.SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
        kernel32.SetThreadPriority.restype = wintypes.BOOL

        kernel32.QueryPerformanceCounter.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
        kernel32.QueryPerformanceCounter.restype = wintypes.BOOL

        kernel32.QueryPerformanceFrequency.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
        kernel32.QueryPerformanceFrequency.restype = wintypes.BOOL

        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HANDLE

    _configure_win32_functions()
else:
    user32 = None
    kernel32 = None
    LRESULT = None
    WNDPROC = None


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise RuntimeError(
            "Windows Raw Input capture requires Windows (sys.platform == 'win32'); "
            f"this process is running on {sys.platform!r}."
        )


# --- pure helpers: device path parsing --------------------------------------
# No Win32 calls here, so these run and are tested on any platform.


def parse_vendor_and_product_id(device_path: str) -> tuple[str, str]:
    """Extract (vendor_id, product_id) as 4-hex-digit strings from a path."""
    match = _VID_PID_PATTERN.search(device_path)
    if not match:
        raise ValueError(f"no VID/PID found in device path: {device_path!r}")
    return match.group(1).upper(), match.group(2).upper()


def derive_pnp_instance_id(device_path: str) -> str:
    """Turn a Raw Input device path into a Windows PnP device instance id.

    For example HID#VID_046D&PID_C52B#7&2f4bb3a7&0&0000#{guid} becomes
    HID\\VID_046D&PID_C52B\\7&2F4BB3A7&0&0000, matching the id pnputil
    expects for enable/disable.
    """
    stripped = device_path
    if stripped.startswith(_DEVICE_PATH_PREFIX):
        stripped = stripped[len(_DEVICE_PATH_PREFIX) :]
    segments = stripped.split("#")
    if len(segments) < 3:
        raise ValueError(f"unexpected device path shape: {device_path!r}")
    return "\\".join(segments[:3]).upper()


def classify_bus_type(device_path: str) -> Literal["USB", "PS2", "Bluetooth", "Unknown"]:
    """Best-effort bus type from a Raw Input device path alone.

    This is a heuristic, not a device-tree query: a laptop's internal
    keyboard is enumerated through the legacy i8042 (PS/2) driver stack
    and shows an ACPI enumerator; most USB HID keyboards carry a VID/PID.
    Bluetooth HID keyboards also carry a VID/PID and are indistinguishable
    from USB by path alone with this approach; see docs/windows_notes.md.
    """
    upper_path = device_path.upper()
    stripped = (
        upper_path[len(_DEVICE_PATH_PREFIX) :]
        if upper_path.startswith(_DEVICE_PATH_PREFIX)
        else upper_path
    )
    enumerator = stripped.split("#", 1)[0]
    if enumerator == "ACPI":
        return "PS2"
    if "VID_" in upper_path and "PID_" in upper_path:
        return "USB"
    return "Unknown"


def _describe_device(bus_type: str, vendor_id: str, product_id: str) -> str:
    if vendor_id == "0000" and product_id == "0000":
        return f"{bus_type} Keyboard"
    return f"{bus_type} Keyboard (VID_{vendor_id} PID_{product_id})"


# --- press/repeat/pairing state, confined to this one class -----------------


class _PressTracker:
    """Pairs key-down/key-up Raw Input events into KeyEvent records.

    Holds (device_id, VKey) -> press_id only while a key is physically
    down, purely to detect OS auto-repeat and to pair a down with its
    matching up. This is the only place in the process that ever holds a
    VKey value. It is never logged, never attached to a KeyEvent, and is
    cleared on reset() (capture stop) or release_device() (device
    removal).
    """

    def __init__(self) -> None:
        self._held: dict[tuple[str, int], int] = {}
        self._next_press_id = itertools.count(1)

    def handle(
        self, device_id: str, vkey: int, is_break: bool
    ) -> tuple[Literal["down", "up"], int, bool]:
        key = (device_id, vkey)

        if is_break:
            press_id = self._held.pop(key, None)
            if press_id is None:
                press_id = next(self._next_press_id)
            return "up", press_id, False

        existing = self._held.get(key)
        if existing is not None:
            return "down", existing, True

        press_id = next(self._next_press_id)
        self._held[key] = press_id
        return "down", press_id, False

    def release_device(self, device_id: str) -> None:
        for key in [held_key for held_key in self._held if held_key[0] == device_id]:
            del self._held[key]

    def reset(self) -> None:
        self._held.clear()


# --- module-level Win32 helpers ----------------------------------------------


def _query_performance_frequency() -> int:
    frequency = ctypes.c_longlong(0)
    kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))
    return frequency.value


def _query_performance_counter() -> int:
    counter = ctypes.c_longlong(0)
    kernel32.QueryPerformanceCounter(ctypes.byref(counter))
    return counter.value


def _raise_current_thread_priority() -> None:
    """Best-effort: reduce timing jitter. Never requires elevation."""
    handle = kernel32.GetCurrentThread()
    kernel32.SetThreadPriority(handle, THREAD_PRIORITY_HIGHEST)


def _read_raw_input(h_raw_input: int) -> RAWINPUT | None:
    """GetRawInputData's two-call size-then-fill pattern."""
    header_size = ctypes.sizeof(RAWINPUTHEADER)
    cb_size = wintypes.UINT(0)

    result = user32.GetRawInputData(
        h_raw_input, RID_INPUT, None, ctypes.byref(cb_size), header_size
    )
    if result != 0 or cb_size.value == 0:
        return None

    buffer = (ctypes.c_byte * cb_size.value)()
    result = user32.GetRawInputData(
        h_raw_input, RID_INPUT, buffer, ctypes.byref(cb_size), header_size
    )
    if result in (0, 0xFFFFFFFF):
        return None

    return ctypes.cast(buffer, ctypes.POINTER(RAWINPUT)).contents


def _get_raw_input_device_name(h_device: int) -> str | None:
    """GetRawInputDeviceInfoW(RIDI_DEVICENAME)'s two-call pattern."""
    size = wintypes.UINT(0)
    user32.GetRawInputDeviceInfoW(h_device, RIDI_DEVICENAME, None, ctypes.byref(size))
    if size.value == 0:
        return None

    buffer = ctypes.create_unicode_buffer(size.value)
    result = user32.GetRawInputDeviceInfoW(h_device, RIDI_DEVICENAME, buffer, ctypes.byref(size))
    if result in (0, 0xFFFFFFFF):
        return None
    return buffer.value


def _create_message_window(class_name: str, wnd_proc_callback: object) -> int:
    h_instance = kernel32.GetModuleHandleW(None)

    wnd_class = WNDCLASSEXW()
    wnd_class.cbSize = ctypes.sizeof(WNDCLASSEXW)
    wnd_class.lpfnWndProc = ctypes.cast(wnd_proc_callback, ctypes.c_void_p)
    wnd_class.hInstance = h_instance
    wnd_class.lpszClassName = class_name

    atom = user32.RegisterClassExW(ctypes.byref(wnd_class))
    if atom == 0:
        last_error = ctypes.get_last_error()
        if last_error != ERROR_CLASS_ALREADY_EXISTS:
            raise ctypes.WinError(last_error)

    hwnd = user32.CreateWindowExW(
        0,
        class_name,
        class_name,
        0,
        0,
        0,
        0,
        0,
        wintypes.HWND(HWND_MESSAGE),
        None,
        h_instance,
        None,
    )
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    return hwnd


def _register_for_keyboard_input(hwnd: int) -> None:
    device = RAWINPUTDEVICE()
    device.usUsagePage = HID_USAGE_PAGE_GENERIC
    device.usUsage = HID_USAGE_GENERIC_KEYBOARD
    device.dwFlags = RIDEV_INPUTSINK | RIDEV_DEVNOTIFY
    device.hwndTarget = hwnd
    if not user32.RegisterRawInputDevices(ctypes.byref(device), 1, ctypes.sizeof(RAWINPUTDEVICE)):
        raise ctypes.WinError(ctypes.get_last_error())


def _unregister_keyboard_input() -> None:
    device = RAWINPUTDEVICE()
    device.usUsagePage = HID_USAGE_PAGE_GENERIC
    device.usUsage = HID_USAGE_GENERIC_KEYBOARD
    device.dwFlags = RIDEV_REMOVE
    device.hwndTarget = None
    user32.RegisterRawInputDevices(ctypes.byref(device), 1, ctypes.sizeof(RAWINPUTDEVICE))


def _run_message_loop() -> None:
    msg = wintypes.MSG()
    while True:
        result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
        if result <= 0:
            break
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


def _refresh_device_list() -> list[tuple[int, int]]:
    """Return (hDevice, dwType) for every currently attached Raw Input device."""
    count = wintypes.UINT(0)
    user32.GetRawInputDeviceList(None, ctypes.byref(count), ctypes.sizeof(RAWINPUTDEVICELIST))
    if count.value == 0:
        return []

    devices = (RAWINPUTDEVICELIST * count.value)()
    result = user32.GetRawInputDeviceList(
        devices, ctypes.byref(count), ctypes.sizeof(RAWINPUTDEVICELIST)
    )
    if result == 0xFFFFFFFF:
        return []
    return [(devices[index].hDevice, devices[index].dwType) for index in range(result)]


# --- the capture backend ------------------------------------------------------


class WindowsRawInputCapture(CaptureSource):
    """Raw Input capture backend for Windows.

    Registers for keyboard Raw Input on a hidden, message-only window
    running on its own high-priority thread, so scheduling jitter
    elsewhere in the process does not smear the cadence being measured.
    Observes only: it cannot and does not intercept, delay or alter any
    keystroke. See docs/windows_notes.md for what that means in
    practice and what this backend cannot do.
    """

    _WINDOW_CLASS_NAME = "ContinuumRawInputCaptureWindow"

    def __init__(
        self,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        put_timeout_seconds: float = DEFAULT_PUT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__(queue_maxsize=queue_maxsize, put_timeout_seconds=put_timeout_seconds)
        _require_windows()
        self._thread: threading.Thread | None = None
        self._hwnd: int | None = None
        self._ready_event = threading.Event()
        self._startup_error: BaseException | None = None
        self._device_cache: dict[int, DeviceInfo] = {}
        self._device_cache_lock = threading.Lock()
        self._press_tracker = _PressTracker()
        self._qpc_frequency = 1
        self._wnd_proc_callback: object | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("capture already started")

        self._ready_event.clear()
        self._startup_error = None
        self._thread = threading.Thread(
            target=self._run, name="continuum-rawinput-capture", daemon=True
        )
        self._thread.start()

        if not self._ready_event.wait(timeout=5.0):
            self._thread = None
            raise RuntimeError("Raw Input capture thread did not start in time")

        if self._startup_error is not None:
            error, self._startup_error = self._startup_error, None
            self._thread = None
            raise error

    def stop(self) -> None:
        thread = self._thread
        if thread is None:
            return

        if self._hwnd is not None:
            user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
        thread.join(timeout=5.0)

        self._thread = None
        self._hwnd = None
        self._press_tracker.reset()
        with self._device_cache_lock:
            self._device_cache.clear()

    def list_devices(self) -> list[DeviceInfo]:
        with self._device_cache_lock:
            return list(self._device_cache.values())

    def _run(self) -> None:
        try:
            _raise_current_thread_priority()
            self._qpc_frequency = _query_performance_frequency() or 1
            self._wnd_proc_callback = WNDPROC(self._wnd_proc)
            self._hwnd = _create_message_window(self._WINDOW_CLASS_NAME, self._wnd_proc_callback)
            _register_for_keyboard_input(self._hwnd)
            self._prime_device_cache()
        except Exception as error:  # noqa: BLE001 - surfaced to start() via _startup_error
            self._startup_error = error
            self._ready_event.set()
            return

        self._ready_event.set()
        try:
            _run_message_loop()
        finally:
            _unregister_keyboard_input()
            if self._hwnd is not None:
                user32.DestroyWindow(self._hwnd)
            self._hwnd = None

    def _prime_device_cache(self) -> None:
        for h_device, dw_type in _refresh_device_list():
            if dw_type == RIM_TYPEKEYBOARD:
                self._resolve_device_id(h_device)

    def _now_ns(self) -> int:
        return (_query_performance_counter() * 1_000_000_000) // self._qpc_frequency

    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        # Timestamp first, before any parsing, to keep jitter out of the
        # measurement.
        timestamp_ns = self._now_ns()

        if msg == WM_INPUT:
            raw = _read_raw_input(lparam)
            if raw is not None and raw.header.dwType == RIM_TYPEKEYBOARD:
                keyboard = raw.data.keyboard
                vkey = keyboard.VKey
                # Fake-key escape sequences carry no real key information
                # and must be dropped before anything else happens.
                if vkey != FAKE_VKEY_ESCAPE:
                    device_id = self._resolve_device_id(raw.header.hDevice)
                    if device_id is not None:
                        is_break = bool(keyboard.Flags & RI_KEY_BREAK)
                        event_type, press_id, is_repeat = self._press_tracker.handle(
                            device_id, vkey, is_break
                        )
                        self._push_event(
                            KeyEvent(
                                device_id=device_id,
                                timestamp_ns=timestamp_ns,
                                event_type=event_type,
                                press_id=press_id,
                                is_repeat=is_repeat,
                            )
                        )
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        if msg == WM_INPUT_DEVICE_CHANGE:
            self._handle_device_change(wparam, lparam)
            return 0

        if msg in (WM_CLOSE, WM_DESTROY):
            user32.PostQuitMessage(0)
            return 0

        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _handle_device_change(self, wparam: int, lparam: int) -> None:
        if wparam == GIDC_ARRIVAL:
            self._resolve_device_id(lparam)
        elif wparam == GIDC_REMOVAL:
            with self._device_cache_lock:
                removed = self._device_cache.pop(lparam, None)
            if removed is not None:
                self._press_tracker.release_device(removed.device_id)

    def _resolve_device_id(self, h_device: int) -> str | None:
        with self._device_cache_lock:
            cached = self._device_cache.get(h_device)
        if cached is not None:
            return cached.device_id

        device_path = _get_raw_input_device_name(h_device)
        if not device_path:
            return None

        try:
            instance_id = derive_pnp_instance_id(device_path)
        except ValueError:
            return None

        try:
            vendor_id, product_id = parse_vendor_and_product_id(device_path)
        except ValueError:
            vendor_id, product_id = "0000", "0000"

        bus_type = classify_bus_type(device_path)
        device_info = DeviceInfo(
            device_id=instance_id,
            vendor_id=vendor_id,
            product_id=product_id,
            name=_describe_device(bus_type, vendor_id, product_id),
            bus_type=bus_type,
            is_usb=(bus_type == "USB"),
            instance_id=instance_id,
            first_seen=datetime.now(UTC),
        )

        with self._device_cache_lock:
            self._device_cache[h_device] = device_info
        return device_info.device_id
