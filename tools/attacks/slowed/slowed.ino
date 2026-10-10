/*
 * Continuum test payload: slowed_injection.
 *
 * Types the same fixed, harmless string as burst.ino, but with a
 * fixed, human-plausible delay between keystrokes (about 120 ms).
 * Constant timing at a human-like speed is still not human: a real
 * person's typing rhythm always has natural variance, which is
 * exactly what Continuum's cadence features are built to notice.
 *
 * Harmless by design: the same guarantees as burst.ino apply here;
 * see that file's header comment and tools/attacks/README.md.
 */

#include <DigiKeyboard.h>

const char *PAYLOAD = "continuum test payload";

// Extra pause, on top of the Digispark bootloader's own startup wait
// (about 5 seconds), before typing starts. Gives time to focus Notepad.
const unsigned long STARTUP_DELAY_MS = 3000;

// Fixed, human-plausible delay between keystrokes.
const unsigned long KEY_DELAY_MS = 120;

void setup() {
  DigiKeyboard.delay(STARTUP_DELAY_MS);

  // Known DigiKeyboard quirk: the very first keystroke after a delay
  // can be dropped on some systems. A no-op keystroke (key code 0, no
  // modifier) primes the connection without typing anything.
  DigiKeyboard.sendKeyStroke(0);

  for (uint8_t i = 0; PAYLOAD[i] != '\0'; i++) {
    DigiKeyboard.print(PAYLOAD[i]);
    DigiKeyboard.delay(KEY_DELAY_MS);
  }
}

void loop() {
  // Intentionally empty. Typing happens exactly once, in setup();
  // a stuck or looping device can never keep typing forever.
}
