/*
 * Continuum test payload: staged (window-based evasion).
 *
 * Waits 10 seconds after setup() starts (on top of the Digispark
 * bootloader's own startup wait, about 5 seconds), then types the
 * same fixed, harmless string as burst.ino in short bursts of 3 to 5
 * characters, with a pause between bursts. Tests whether Continuum's
 * sliding detection window still catches an attack that is
 * deliberately broken up rather than sent as one continuous run.
 *
 * Harmless by design: the same guarantees as burst.ino apply here;
 * see that file's header comment and tools/attacks/README.md.
 */

#include <DigiKeyboard.h>
#include <string.h>

// The harmless phrase six times (137 characters). Continuum needs 30
// key presses to form one detection window and two flagged windows to
// block, so it can never react to anything shorter than 40 presses; a
// single 22-character phrase would end before detection could start.
const char *PAYLOAD =
    "continuum test payload continuum test payload continuum test payload "
    "continuum test payload continuum test payload continuum test payload";

// Measured from the start of setup(), after the bootloader's own
// separate wait has already elapsed. Gives plenty of time to focus
// Notepad, including after the board has already enumerated.
const unsigned long STARTUP_DELAY_MS = 10000;

// Pause between bursts of characters.
const unsigned long BURST_PAUSE_MS = 600;

const uint8_t MIN_BURST_LENGTH = 3;
const uint8_t MAX_BURST_LENGTH = 5;

void setup() {
  DigiKeyboard.delay(STARTUP_DELAY_MS);

  // There is no hardware random source on the ATtiny85; micros() since
  // power-on is unpredictable enough to seed a non-cryptographic burst
  // length generator for this harmless test payload.
  randomSeed(micros());

  // Known DigiKeyboard quirk: the very first keystroke after a delay
  // can be dropped on some systems. A no-op keystroke (key code 0, no
  // modifier) primes the connection without typing anything.
  DigiKeyboard.sendKeyStroke(0);

  uint8_t length = strlen(PAYLOAD);
  uint8_t i = 0;
  while (i < length) {
    uint8_t burstLength = random(MIN_BURST_LENGTH, MAX_BURST_LENGTH + 1);
    for (uint8_t j = 0; j < burstLength && i < length; j++, i++) {
      DigiKeyboard.print(PAYLOAD[i]);
    }
    DigiKeyboard.delay(BURST_PAUSE_MS);
  }
}

void loop() {
  // Intentionally empty. Typing happens exactly once, in setup();
  // a stuck or looping device can never keep typing forever.
}
