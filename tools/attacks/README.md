# Test payloads for the HID Firewall

Four Digispark (ATtiny85) sketches, one per cadence profile Continuum's
detection model is evaluated against in `docs/eval_results.md`:

| Sketch | Profile | What it does |
| --- | --- | --- |
| `burst/burst.ino` | burst_injection | Types the payload with the minimum delay between keys the library can manage. |
| `slowed/slowed.ino` | slowed_injection | Types the payload with a fixed, human-plausible delay (about 120 ms) between keys. |
| `randomized/randomized.ino` | randomized_injection | Types the payload with a randomised per-key delay (80 to 220 ms), the evasion case. |
| `staged/staged.ino` | window-based evasion | Waits 10 seconds, then types the payload in short bursts of 3 to 5 characters with pauses between them. |

## These are harmless on purpose

Every sketch types exactly one fixed string, `"continuum test
payload"`, into whatever window currently has focus, once, and then
idles forever. None of them:

- open a shell, a Run dialog, or any other program,
- download, execute, exfiltrate or modify anything,
- send a Win, Ctrl or Alt combination (only plain characters and the
  Shift that a real keyboard also uses for capitals and punctuation),
- repeat the payload. `loop()` is intentionally empty in every sketch,
  so a device that gets stuck cannot keep typing.

Do not change the payload to anything you would not want typed into a
real document, and do not add modifier key combinations. If you want
to test a different string, keep it to plain, harmless text.

## What you need

- A Digispark board (ATtiny85), or a compatible clone such as a
  Digispark-flavoured development board sold for keystroke-injection
  testing. This is what the project calls "the Digispark" throughout.
- A Windows 10 or 11 machine with a free USB port.
- [Arduino IDE 2.x](https://www.arduino.cc/en/software).
- A second, real keyboard plugged in before you start testing. See
  "How to test safely" below; this is not optional.

## Installing Digispark board support in Arduino IDE 2.x

1. Open Arduino IDE, then **File > Preferences**.
2. In **Additional boards manager URLs**, add:

   ```
   http://digistump.com/package_digistump_index.json
   ```

   If that URL times out or the connection is refused (this happens on
   some networks; Digistump's own server is not always reliable over
   plain HTTP), use this mirror instead, which carries the same index:

   ```
   https://raw.githubusercontent.com/digistump/arduino-boards-index/master/package_digistump_index.json
   ```

3. **Tools > Board > Boards Manager**, search for `digistump`, and
   install **Digistump AVR Boards**. This also installs the
   `DigiKeyboard` library these sketches use; you do not need to
   install it separately from the Library Manager.
4. **Tools > Board**, select **Digistump AVR Boards > Digispark
   (Default - 16.5mhz)**. This is the only board entry these sketches
   are written for.

You do not need to select a serial port; the Digispark has none until
it is actually plugged in, and even then it only enumerates briefly as
a bootloader, not as a normal COM port.

## Installing the Windows driver

Installing the board package above also downloads the Digistump
driver installer to your machine, under your Arduino data folder:

```
%LOCALAPPDATA%\Arduino15\packages\digistump\tools\micronucleus\<version>\Install Digistump Drivers.bat
```

(`<version>` is whatever Micronucleus version the Boards Manager
installed, for example `2.0a4`.) Run that `.bat` file as Administrator
and accept the driver install prompts. It installs the WinUSB-based
driver Windows needs to recognise the Digispark's bootloader during
the few seconds after it is plugged in.

### Common Windows driver problems and fixes

- **Device Manager shows an unknown device with a yellow warning
  triangle when you plug the board in.** The driver is not installed,
  or was not installed as Administrator. Re-run `Install Digistump
  Drivers.bat` as Administrator, then unplug and replug the board.
- **The driver installer itself is blocked by SmartScreen.** Click
  "More info", then "Run anyway". The installer and its drivers are
  signed, but an unrecognised publisher can still trigger a prompt on
  a fresh machine.
- **Upload fails with something like "micronucleus not found" or "no
  device found".** The Digispark's bootloader window is only about 5
  seconds after power is applied. In Arduino IDE, click **Upload**
  first; the IDE will print "Plug in device now... (will timeout in X
  seconds)". Only plug the board in after you see that message, not
  before.
- **It worked once, then stopped being recognised.** Unplug the board,
  open Device Manager, and check whether it is listed (even
  problematically) under **libusb-win32 devices** or **Universal
  Serial Bus devices**. If it is listed with an error, right click it,
  **Uninstall device**, then unplug, replug, and try the upload again.
- **64-bit vs 32-bit driver installer.** `Install Digistump
  Drivers.bat` picks the right one automatically; if you are running
  the installers by hand instead, use `DPinst64.exe` on virtually any
  Windows 10 or 11 machine today, `DPinst.exe` only on 32-bit Windows.

## Uploading a sketch

1. Open the sketch, for example `tools/attacks/burst/burst.ino`, in
   Arduino IDE. Each sketch must stay in its own folder with a
   matching name (`burst/burst.ino`, not a loose `.ino` file); that is
   an Arduino requirement, not a Continuum one.
2. Confirm the board is still set to **Digispark (Default -
   16.5mhz)**.
3. Click **Upload**. Do not plug the board in yet.
4. Wait for the IDE to print that it is waiting for the device, then
   plug the Digispark into a USB port.
5. Wait for "Upload complete" (or similar). The sketch is now stored
   on the board and starts running every time it gets power, with no
   IDE connection needed.
6. Unplug the board. It is now a standalone test device for that one
   payload.

Repeat per sketch if you want more than one payload available at once;
one physical Digispark can only hold one sketch at a time, so either
reflash it between payloads or use a separate board per payload if you
have more than one.

## How to test safely

Follow this every time, not just the first time:

1. **Focus Notepad.** Open Notepad, click inside the empty document so
   the text cursor is blinking there. This is where the harmless
   payload will land; it must never land in a password field, a
   terminal, or a Run dialog.
2. **Keep a second, real keyboard attached.** Continuum's safety rails
   refuse to disable a device if doing so would leave zero other
   enabled keyboards attached. If the Digispark is the
   only keyboard-class device on the machine, `lock_and_disable` mode
   will correctly refuse to disable it, and you will not get a
   realistic test of that path.
3. **Run the Continuum runtime, elevated.** Open an Administrator
   PowerShell and run `.\tasks.ps1 run-runtime` (or `just
   run-runtime`). Confirm it prints `Elevated: True` and the mode you
   expect. Without elevation, disabling a device is refused by design
   and the response degrades to lock-only; see
   `src/continuum/response/blocker_windows.py`.
4. **Plug the Digispark in.** Wait out its startup delay (the
   bootloader's own wait plus the sketch's own `STARTUP_DELAY_MS`;
   `staged.ino` waits 10 seconds total). The payload types into
   Notepad, and then the device goes idle for good.
5. **Watch for the response.** Depending on the configured mode, the
   workstation should lock, and Device Manager should show the
   Digispark disabled, within a window or two of detection. After you
   log back in, a toast notification should be waiting.
6. **Unplug the Digispark after every test.** Do not leave it attached
   between runs. If it still shows disabled in Device Manager, either
   wait for auto-release (`auto_release_timeout_seconds` in
   `config/default.yaml`, 10 minutes by default) or clear it
   immediately with the kill switch:

   ```
   python -m continuum.runtime --release-all
   ```

7. **Clear Notepad between runs** (Ctrl+A, Delete) so each run's
   output does not pile up and confuse you about which run typed what.

## Recording results

`docs/hardware_results.md` is a template with the expected verdict per
payload and a table for 5 runs each, for your own notes.
`tools/run_hardware_trial.py` watches the same runs automatically and
writes `docs/hardware_trial_results.csv` with time-to-detect (in
milliseconds and in keystrokes) and time-to-lock per payload. Run it
in its own terminal, alongside the elevated runtime:

```
python tools/run_hardware_trial.py
```

It prompts for which payload you are about to test, then waits for the
runtime to detect and record a matching incident before prompting for
the next run.
