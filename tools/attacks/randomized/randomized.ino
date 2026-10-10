/*
 * Continuum test payload: randomized_injection.
 *
 * Types the same fixed, harmless string as burst.ino, with a random
 * per-key delay drawn from a human-plausible range (80 to 220 ms).
 * This is the evasion case: an attacker trying to defeat a
 * timing-only detector by making the interval between keys look less
 * mechanical than a fixed delay would.
 *
 * Harmless by design: the same guarantees as burst.ino apply here;
 * see that file's header comment and tools/attacks/README.md.
 */

#include <DigiKeyboard.h>

const char *PAYLOAD = "continuum test payload";

// Extra pause, on top of the Digispark bootloader's own startup wait
// (about 5 seconds), before typing starts. Gives time to focus Notepad.
const unsigned long STARTUP_DELAY_MS = 3000;

// Human-plausible range for the randomised per-key delay.
const unsigned long MIN_KEY_DELAY_MS = 80;
const unsigned long MAX_KEY_DELAY_MS = 220;

void setup() {
  DigiKeyboard.delay(STARTUP_DELAY_MS);

  // There is no hardware random source on the ATtiny85; micros() since
  // power-on is unpredictable enough to seed a non-cryptographic delay
  // generator for this harmless test payload.
  randomSeed(micros());

  // Known DigiKeyboard quirk: the very first keystroke after a delay
  // can be dropped on some systems. A no-op keystroke (key code 0, no
  // modifier) primes the connection without typing anything.
  DigiKeyboard.sendKeyStroke(0);

  for (uint8_t i = 0; PAYLOAD[i] != '\0'; i++) {
    DigiKeyboard.print(PAYLOAD[i]);
    long delayMs = random(MIN_KEY_DELAY_MS, MAX_KEY_DELAY_MS + 1);
    DigiKeyboard.delay(delayMs);
  }
}

void loop() {
  // Intentionally empty. Typing happens exactly once, in setup();
  // a stuck or looping device can never keep typing forever.
}
