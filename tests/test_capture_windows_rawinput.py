"""Tests for continuum.capture.windows_rawinput.

Every Win32 call is mocked; nothing here creates a real window, reads a
real device, or touches real hardware. Covers device-path parsing,
device-id mapping and caching, repeat detection and down/up pairing, the
0xFF fake-key filter, and the hard rule that no key code, scan code or
virtual-key value ever survives into an emitted KeyEvent or into any log
line.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from continuum.capture import windows_rawinput as rawinput
from continuum.capture.windows_rawinput import (
    RI_KEY_BREAK,
    RIM_TYPEKEYBOARD,
    WM_INPUT,
    WindowsRawInputCapture,
    _PressTracker,
    classify_bus_type,
    derive_pnp_instance_id,
    parse_vendor_and_product_id,
)
from continuum.common.schemas import SOFTWARE_INPUT_DEVICE_ID

USB_KEYBOARD_PATH = (
    r"\\?\HID#VID_046D&PID_C52B&MI_00#7&2f4bb3a7&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}"
)
PS2_KEYBOARD_PATH = r"\\?\ACPI#PNP0303#4&1a2b3c4&0#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}"


def _fake_raw_input(h_device: int, vkey: int, flags: int) -> SimpleNamespace:
    keyboard = SimpleNamespace(
        VKey=vkey, Flags=flags, MakeCode=0, Reserved=0, Message=0, ExtraInformation=0
    )
    header = SimpleNamespace(hDevice=h_device, dwType=RIM_TYPEKEYBOARD, dwSize=0, wParam=0)
    return SimpleNamespace(header=header, data=SimpleNamespace(keyboard=keyboard))


@pytest.fixture
def capture(monkeypatch):
    # Every test here mocks user32 so nothing touches a real window.
    monkeypatch.setattr(rawinput, "user32", MagicMock())
    instance = WindowsRawInputCapture()
    yield instance


# --- device path parsing: pure functions, no mocking needed ----------------


def test_parse_vendor_and_product_id():
    assert parse_vendor_and_product_id(USB_KEYBOARD_PATH) == ("046D", "C52B")


def test_parse_vendor_and_product_id_raises_when_absent():
    with pytest.raises(ValueError):
        parse_vendor_and_product_id(PS2_KEYBOARD_PATH)


def test_derive_pnp_instance_id():
    expected = r"HID\VID_046D&PID_C52B&MI_00\7&2F4BB3A7&0&0000"
    assert derive_pnp_instance_id(USB_KEYBOARD_PATH) == expected


def test_derive_pnp_instance_id_rejects_too_short_a_path():
    with pytest.raises(ValueError):
        derive_pnp_instance_id(r"\\?\ONLYONE")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (USB_KEYBOARD_PATH, "USB"),
        (PS2_KEYBOARD_PATH, "PS2"),
        (r"\\?\SOMETHING#WEIRD#NO-IDS", "Unknown"),
    ],
)
def test_classify_bus_type(path, expected):
    assert classify_bus_type(path) == expected


# --- _PressTracker: pure logic, no mocking needed ---------------------------


def test_press_tracker_down_then_up_share_a_press_id():
    tracker = _PressTracker()

    event_type, press_id, is_repeat = tracker.handle("dev", 65, is_break=False)
    assert event_type == "down"
    assert is_repeat is False

    event_type, up_press_id, is_repeat = tracker.handle("dev", 65, is_break=True)
    assert event_type == "up"
    assert up_press_id == press_id
    assert is_repeat is False


def test_press_tracker_detects_os_auto_repeat():
    tracker = _PressTracker()
    _, first_id, _ = tracker.handle("dev", 65, is_break=False)
    event_type, second_id, is_repeat = tracker.handle("dev", 65, is_break=False)

    assert event_type == "down"
    assert is_repeat is True
    assert second_id == first_id


def test_press_tracker_up_without_a_prior_down_still_emits_an_event():
    tracker = _PressTracker()
    event_type, press_id, is_repeat = tracker.handle("dev", 65, is_break=True)

    assert event_type == "up"
    assert is_repeat is False
    assert isinstance(press_id, int)


def test_press_tracker_distinguishes_devices_with_the_same_vkey():
    tracker = _PressTracker()
    _, id_a, _ = tracker.handle("dev-a", 65, is_break=False)
    _, id_b, _ = tracker.handle("dev-b", 65, is_break=False)

    assert id_a != id_b


def test_press_tracker_release_device_clears_only_that_device():
    tracker = _PressTracker()
    tracker.handle("dev-a", 65, is_break=False)
    tracker.handle("dev-b", 65, is_break=False)

    tracker.release_device("dev-a")

    _, _, is_repeat_a = tracker.handle("dev-a", 65, is_break=False)
    _, _, is_repeat_b = tracker.handle("dev-b", 65, is_break=False)
    assert is_repeat_a is False
    assert is_repeat_b is True


def test_press_tracker_reset_clears_everything():
    tracker = _PressTracker()
    tracker.handle("dev", 65, is_break=False)
    tracker.reset()

    _, _, is_repeat = tracker.handle("dev", 65, is_break=False)
    assert is_repeat is False


# --- _require_windows --------------------------------------------------------


def test_require_windows_raises_when_not_windows(monkeypatch):
    monkeypatch.setattr(rawinput, "IS_WINDOWS", False)
    with pytest.raises(RuntimeError, match="Windows"):
        rawinput._require_windows()


# --- device-id resolution and caching ---------------------------------------


def test_resolve_device_id_parses_a_usb_hid_path_and_caches(capture, monkeypatch):
    calls = []
    monkeypatch.setattr(
        rawinput,
        "_get_raw_input_device_name",
        lambda h_device: (calls.append(h_device), USB_KEYBOARD_PATH)[1],
    )

    first = capture._resolve_device_id(123)
    second = capture._resolve_device_id(123)

    assert first == second
    assert calls == [123]  # only resolved once; the second call hit the cache

    [device] = capture.list_devices()
    assert device.vendor_id == "046D"
    assert device.product_id == "C52B"
    assert device.bus_type == "USB"
    assert device.is_usb is True
    assert device.instance_id == r"HID\VID_046D&PID_C52B&MI_00\7&2F4BB3A7&0&0000"


def test_resolve_device_id_handles_a_ps2_path_without_vid_pid(capture, monkeypatch):
    monkeypatch.setattr(rawinput, "_get_raw_input_device_name", lambda h_device: PS2_KEYBOARD_PATH)

    capture._resolve_device_id(999)

    [device] = capture.list_devices()
    assert device.bus_type == "PS2"
    assert device.is_usb is False
    assert device.vendor_id == "0000"
    assert device.product_id == "0000"


def test_resolve_device_id_returns_none_without_a_device_path(capture, monkeypatch):
    monkeypatch.setattr(rawinput, "_get_raw_input_device_name", lambda h_device: None)

    assert capture._resolve_device_id(1) is None
    assert capture.list_devices() == []


def test_handle_device_change_removal_releases_held_keys(capture, monkeypatch):
    monkeypatch.setattr(rawinput, "_get_raw_input_device_name", lambda h_device: USB_KEYBOARD_PATH)
    device_id = capture._resolve_device_id(123)
    capture._press_tracker.handle(device_id, 65, is_break=False)

    capture._handle_device_change(rawinput.GIDC_REMOVAL, 123)

    assert capture.list_devices() == []
    # The held key for that device was released, so pressing it "again"
    # looks like a fresh press, not a repeat.
    _, _, is_repeat = capture._press_tracker.handle(device_id, 65, is_break=False)
    assert is_repeat is False


# --- WM_INPUT dispatch: event conversion and the 0xFF filter ---------------


def test_wnd_proc_converts_a_key_down_into_a_key_event(capture, monkeypatch):
    monkeypatch.setattr(capture, "_resolve_device_id", lambda h_device: "device-1")
    monkeypatch.setattr(capture, "_now_ns", lambda: 42)
    monkeypatch.setattr(
        rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(1, vkey=65, flags=0)
    )

    capture._wnd_proc(hwnd=0, msg=WM_INPUT, wparam=0, lparam=1)

    event = capture.events.get_nowait()
    assert event.device_id == "device-1"
    assert event.event_type == "down"
    assert event.timestamp_ns == 42
    assert event.is_repeat is False
    expected_fields = {"device_id", "timestamp_ns", "event_type", "press_id", "is_repeat"}
    assert set(event.model_dump()) == expected_fields


def test_wnd_proc_tags_input_with_no_device_handle_as_software_input(capture, monkeypatch):
    # SendInput (remote-access tools, macros) arrives with hDevice NULL.
    monkeypatch.setattr(
        capture, "_resolve_device_id", lambda h_device: pytest.fail("must not resolve NULL")
    )
    monkeypatch.setattr(capture, "_now_ns", lambda: 42)
    monkeypatch.setattr(
        rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(0, vkey=65, flags=0)
    )

    capture._wnd_proc(hwnd=0, msg=WM_INPUT, wparam=0, lparam=1)

    event = capture.events.get_nowait()
    assert event.device_id == SOFTWARE_INPUT_DEVICE_ID
    assert event.event_type == "down"
    assert set(event.model_dump()) == {
        "device_id", "timestamp_ns", "event_type", "press_id", "is_repeat"
    }


def test_wnd_proc_filters_the_fake_vkey_escape_sequence(capture, monkeypatch):
    monkeypatch.setattr(capture, "_resolve_device_id", lambda h_device: "device-1")
    monkeypatch.setattr(capture, "_now_ns", lambda: 42)
    monkeypatch.setattr(
        rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(1, vkey=0xFF, flags=0)
    )

    capture._wnd_proc(hwnd=0, msg=WM_INPUT, wparam=0, lparam=1)

    assert capture.events.empty()


def test_wnd_proc_detects_repeat_and_pairs_up_with_the_matching_down(capture, monkeypatch):
    monkeypatch.setattr(capture, "_resolve_device_id", lambda h_device: "device-1")
    timestamps = iter([10, 20, 30])
    monkeypatch.setattr(capture, "_now_ns", lambda: next(timestamps))

    monkeypatch.setattr(rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(1, 65, 0))
    capture._wnd_proc(0, WM_INPUT, 0, 1)
    first = capture.events.get_nowait()

    monkeypatch.setattr(rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(1, 65, 0))
    capture._wnd_proc(0, WM_INPUT, 0, 1)
    second = capture.events.get_nowait()

    monkeypatch.setattr(
        rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(1, 65, RI_KEY_BREAK)
    )
    capture._wnd_proc(0, WM_INPUT, 0, 1)
    third = capture.events.get_nowait()

    assert first.event_type == "down" and first.is_repeat is False
    assert second.event_type == "down" and second.is_repeat is True
    assert second.press_id == first.press_id
    assert third.event_type == "up" and third.press_id == first.press_id
    assert third.is_repeat is False


def test_wnd_proc_ignores_non_keyboard_raw_input(capture, monkeypatch):
    monkeypatch.setattr(capture, "_now_ns", lambda: 1)
    non_keyboard = _fake_raw_input(1, vkey=65, flags=0)
    non_keyboard.header.dwType = 0  # RIM_TYPEMOUSE
    monkeypatch.setattr(rawinput, "_read_raw_input", lambda lparam: non_keyboard)

    capture._wnd_proc(hwnd=0, msg=WM_INPUT, wparam=0, lparam=1)

    assert capture.events.empty()


def test_no_key_identity_survives_into_the_emitted_event_or_any_output(
    capture, monkeypatch, capsys
):
    monkeypatch.setattr(capture, "_resolve_device_id", lambda h_device: "device-1")
    monkeypatch.setattr(capture, "_now_ns", lambda: 1)
    secret_vkey = 0x41
    monkeypatch.setattr(
        rawinput, "_read_raw_input", lambda lparam: _fake_raw_input(1, secret_vkey, 0)
    )

    capture._wnd_proc(hwnd=0, msg=WM_INPUT, wparam=0, lparam=1)
    event = capture.events.get_nowait()

    dumped = event.model_dump()
    assert set(dumped) == {"device_id", "timestamp_ns", "event_type", "press_id", "is_repeat"}
    assert secret_vkey not in dumped.values()

    captured = capsys.readouterr()
    assert str(secret_vkey) not in captured.out
    assert str(secret_vkey) not in captured.err
