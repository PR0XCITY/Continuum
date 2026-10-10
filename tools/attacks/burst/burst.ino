/*
 * Continuum test payload: burst_injection.
 *
 * Types one fixed, harmless string into whatever window currently has
 * focus, with the minimum delay the DigiKeyboard library can manage
 * between keystrokes (no delay is inserted deliberately; USB polling
 * overhead alone sets the pace). This is the classic fast-injection
 * profile Continuum's HID Firewall is built to catch.
 *
 * Harmless by design:
 *   - the payload is plain text only, nothing else,
 *   - it never opens a shell, downloads, executes, or exfiltrates
 *     anything, and never modifies any file or setting,
 *   - it never sends a Win, Ctrl or Alt combination,
 *   - after typing once, the device idles forever; it never repeats
 *     the payload, so a stuck device cannot keep typing.
 *
 * Safe test procedure: focus a plain text editor (Notepad) before
 * plugging the board in. See tools/attacks/README.md.
 */

#include <DigiKeyboard.h>

// The harmless phrase six times (137 characters). Continuum needs 30
// key presses to form one detection window and two flagged windows to
// block, so it can never react to anything shorter than 40 presses; a
// single 22-character phrase would end before detection could start.
const char *PAYLOAD =
    "continuum test payload continuum test payload continuum test payload "
    "continuum test payload continuum test payload continuum test payload";

// Extra pause, on top of the Digispark bootloader's own startup wait
// (about 5 seconds), before typing starts. Gives time to focus Notepad.
const unsigned long STARTUP_DELAY_MS = 3000;

void setup() {
  DigiKeyboard.delay(STARTUP_DELAY_MS);

  // Known DigiKeyboard quirk: the very first keystroke after a delay
  // can be dropped on some systems. A no-op keystroke (key code 0, no
  // modifier) primes the connection without typing anything.
  DigiKeyboard.sendKeyStroke(0);

  DigiKeyboard.print(PAYLOAD);
}

void loop() {
  // Intentionally empty. Typing happens exactly once, in setup();
  // a stuck or looping device can never keep typing forever.
}
