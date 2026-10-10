# Hardware trial results

Template for recording real Digispark runs against the HID Firewall.
See `tools/attacks/README.md` for the safe test procedure before using
this. `tools/run_hardware_trial.py` records the same runs automatically
into `docs/hardware_trial_results.csv`; use this file for your own
notes and for anything the script cannot see (did the toast actually
appear, did the screen actually lock, anything unexpected).

Before each run: Notepad focused, second keyboard attached, runtime
running elevated, Continuum's model trained on your own baseline.
After each run: unplug the Digispark, confirm it shows released (wait
for auto-release or run `python -m continuum.runtime --release-all`),
clear Notepad.

## Test matrix

| Payload | Expected verdict | Why |
| --- | --- | --- |
| burst | blocked | Near-constant 1 to 10 ms intervals are the clearest possible departure from human cadence; see docs/eval_results.md. |
| slowed | blocked | Constant timing has zero natural variance regardless of absolute speed, which human typing never has. |
| randomized | suspicious or normal (often missed) | Deliberately tuned to a human-plausible mean and spread; a timing-only detector is expected to struggle with this one. |
| staged | blocked, but slower to confirm | Broken into short bursts with pauses, to test whether the sliding window and debounce still catch a deliberately interrupted attack. |

These are what the model typically does, not a guarantee; the actual
verdict depends on your own trained baseline and calibration.

## Results: burst

| Run | Date/time | Verdict | Action taken | Time to detect (ms) | Time to detect (keystrokes) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |

## Results: slowed

| Run | Date/time | Verdict | Action taken | Time to detect (ms) | Time to detect (keystrokes) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |

## Results: randomized

| Run | Date/time | Verdict | Action taken | Time to detect (ms) | Time to detect (keystrokes) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |

## Results: staged

| Run | Date/time | Verdict | Action taken | Time to detect (ms) | Time to detect (keystrokes) | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |
| 2 |  |  |  |  |  |  |
| 3 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 5 |  |  |  |  |  |  |

## Summary

Fill in once all 20 runs are done.

- Recall per payload (blocked runs out of 5):
  - burst:
  - slowed:
  - randomized:
  - staged:
- False positives while testing (did normal typing on your own keyboard ever get flagged):
- Anything that did not match the expected verdict, and your best guess why:
