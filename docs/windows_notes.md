# Windows Raw Input notes

This document explains how `src/continuum/capture/windows_rawinput.py`
captures keystroke timing, why it uses the Raw Input API instead of a
keyboard hook, and what it deliberately cannot do.

## How Raw Input works here

1. A dedicated thread creates a hidden, message-only window
   (`HWND_MESSAGE`). A message-only window has no visible surface and
   cannot be clicked, resized or seen in any taskbar; it exists purely
   to receive window messages. That thread's priority is raised to
   `THREAD_PRIORITY_HIGHEST` so OS scheduling jitter elsewhere in the
   process does not smear the timing we are trying to measure. Neither
   step needs Administrator rights.
2. The window calls `RegisterRawInputDevices` for usage page `0x01`
   (generic desktop), usage `0x06` (keyboard), with
   `RIDEV_INPUTSINK | RIDEV_DEVNOTIFY`. `RIDEV_INPUTSINK` means the
   window keeps receiving input even though it is never focused (it
   cannot be, it is not visible). `RIDEV_DEVNOTIFY` means Windows also
   tells us when a keyboard-class device arrives or is removed, so a
   newly plugged-in USB keyboard, or a Digispark that enumerates as a
   keyboard, shows up without restarting Continuum.
3. Every keystroke arrives as a `WM_INPUT` message. The handler:
   - reads the Raw Input data with `GetRawInputData`,
   - reads `RAWINPUTHEADER.hDevice` to know which physical device this
     came from,
   - reads `RAWKEYBOARD.Flags` to tell key-down from key-up
     (`RI_KEY_BREAK`),
   - discards the event entirely if `VKey == 0xFF`, a fake-key escape
     sequence some extended keys send as a harmless placeholder,
   - timestamps the event with `QueryPerformanceCounter`, converted to
     nanoseconds, taken as the first thing the handler does, before any
     parsing.
4. `hDevice` is a stable handle for one physical device for as long as
   it stays attached. The first time we see a handle, we resolve it to
   a device path with `GetRawInputDeviceInfo(RIDI_DEVICENAME)`, for
   example:

   ```
   \\?\HID#VID_046D&PID_C52B&MI_00#7&2f4bb3a7&0&0000#{guid}
   ```

   The vendor and product id come straight out of that path. The PnP
   device instance id that `pnputil` expects is the same path with the
   `\\?\` prefix dropped, `#` replaced by `\`, and the trailing
   interface-GUID segment dropped:

   ```
   HID\VID_046D&PID_C52B&MI_00\7&2F4BB3A7&0&0000
   ```

   The result is cached by `hDevice` so we only parse it once per
   device per session; the cache is refreshed on `WM_INPUT_DEVICE_CHANGE`
   arrival and cleared for that device on removal.

## Why Raw Input instead of a keyboard hook

A low-level keyboard hook (`SetWindowsHookEx` with `WH_KEYBOARD_LL`)
sees every keystroke in the system, but it cannot tell which physical
device produced it; synthesized input from a HID-emulating attack
device looks, to a hook, identical to a human typing on the built-in
keyboard. Since the entire premise of the HID Firewall is "analyse
cadence per physical device and disable only the offending one," a
hook cannot do the one thing this project needs. Raw Input can, because
`RAWINPUTHEADER.hDevice` identifies the originating device directly.

## Known limits

- **Observe only, no interception.** Raw Input is a notification
  mechanism. Continuum sees a keystroke after the fact; it cannot
  delay, drop or rewrite it, and this backend makes no attempt to.
  The only intervention point in this project is the response layer
  disabling the offending device afterwards (`pnputil`) and locking the
  workstation, which happens on the order of a detection window's
  worth of keystrokes after the attack starts, not before the first
  one.
- **Bus type is a heuristic, not a device-tree query.** This backend
  classifies a device as `"PS2"` if its Raw Input path's enumerator is
  `ACPI` (how a laptop's built-in keyboard is usually enumerated,
  through the legacy i8042 driver stack), as `"USB"` if the path
  carries a `VID_`/`PID_` pair, and `"Unknown"` otherwise. Bluetooth HID
  keyboards also carry a `VID_`/`PID_` pair and are currently classified
  as `"USB"`; distinguishing them reliably needs a device-tree query
  (SetupAPI / CfgMgr32) that this backend does not perform, to keep the
  implementation to the Raw Input and basic Win32 surface. In practice, some Bluetooth LE HID devices use a path like
  `...Dev_VID&02000E_PID&3412...` (`VID&`/`PID&`, not `VID_`/`PID_`),
  which this backend's parser does not match at all; those devices fall
  through to `"Unknown"` with the `"0000"`/`"0000"` placeholder below,
  a safe, honest result rather than a wrong guess.
- **No real vendor/product id for PS/2-class devices.** A device whose
  path has no `VID_`/`PID_` (most built-in laptop keyboards) is given
  the placeholder `vendor_id`/`product_id` of `"0000"`/`"0000"`.
  `bus_type` and `instance_id` are what actually distinguish it from
  other devices, not vendor/product id.
- **`DeviceInfo.name` is synthesized, not the OS's friendly device
  name.** Getting the real driver-reported friendly name needs
  SetupAPI device property queries; this backend instead builds a
  readable label like `"USB Keyboard (VID_046D PID_C52B)"` from the
  bus type and ids it already has.
- **Needs a window station.** A message-only window still needs the
  calling thread to have access to a window station (every interactive
  logon session has one by default). This backend will not work inside
  a true headless Windows service running under a session with no
  window station at all; it is designed to run as a regular, unprivileged
  process in the logged-in user's session.
- **Capture itself needs no elevation.** Everything in this file,
  including raising the capture thread's priority, runs unprivileged.
  Only the response layer's device disable/enable, via `pnputil`, needs
  an elevated process; see `src/continuum/response/`.
