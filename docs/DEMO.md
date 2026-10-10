# Five-minute demo

A scripted walk-through of the whole loop: normal typing, a keystroke
injection being blocked, the incident in the dashboard, IncidentRAG
answering and refusing, an attack Continuum misses, and releasing
everything. Every command is run from the repository root in PowerShell.

## Before the demo (allow 30 minutes, once)

Do these well before the audience arrives; none of them belong in the five
minutes.

1. **Install and set up.** Follow the README: `.\tasks.ps1 setup`, then
   `ollama pull llama3.1:8b`.
2. **Train on your own typing.** Run `.\tasks.ps1 record-baseline` two or
   three times on the keyboard you will demo with, about 3 minutes each.
   Include one fast session. Then run `.\tasks.ps1 train-model`.
3. **Flash two Digisparks**, one with `tools/attacks/burst/burst.ino` and
   one with `tools/attacks/randomized/randomized.ino` (see
   `tools/attacks/README.md`). Label them. With only one board, flash the
   randomized sketch after part f is announced, or skip part f.
4. **Keep a second keyboard attached** (for a laptop, the built-in one
   counts). Continuum never disables the last keyboard, and you need one
   to unlock the screen.
5. **Optional: give the dashboard some history** with
   `.\tasks.ps1 seed-demo` while the API is running. These 200 incidents
   are synthetic and labelled as such in their notes.
6. **Start everything:** `.\tasks.ps1 run-all`, and approve the
   administrator prompt for the runtime. Three windows open: Continuum
   api, Continuum dashboard and Continuum runtime. Check that the runtime
   window says
   `Continuum runtime starting. Response mode: lock_and_disable. Elevated: True.`
7. **Open the dashboard** at http://127.0.0.1:8501 and Notepad, and
   arrange them side by side.

## a) Normal typing is unaffected (0:00 to 0:40)

Type a few sentences into Notepad at your normal speed.

Expected:
- Nothing locks and nothing is disabled.
- On the dashboard's **Live status** page, your keyboard has a green
  `NORMAL` badge.
- The **Inter-key interval, last 60 seconds** chart draws a line for it.
- The **Runtime** card says Running, with a heartbeat a few seconds old.

Say: Continuum only ever sees timing, never which keys were pressed. It
compares the rhythm of each physical keyboard with your recorded baseline.

## b) A keystroke injection is blocked (0:40 to 1:40)

Click into Notepad, then plug in the **burst** Digispark.

Expected:
1. For about 5 seconds nothing happens (the Digispark's bootloader), then
   another 3 seconds (the sketch's startup delay).
2. `continuum test payload` starts appearing at machine speed, and within
   about half a second **the screen locks**. Roughly 40 characters land
   in Notepad first. That is expected; see part f and the README's known
   limitations.
3. The runtime window logs the block, the disable and
   `posted incident ...`.
4. Unlock with your own keyboard. A Windows notification,
   **Continuum: device blocked**, says the device was blocked
   (`locked_and_disabled`).
5. The Digispark is disabled. In Device Manager (`devmgmt.msc`, Keyboards)
   it has a down-arrow icon, and on the Live status page it has a red
   `BLOCKED` badge marked "disabled by Continuum".

Say: lock happens first because anything typed after the lock goes into
the password box, not into a terminal. The device is disabled with
`pnputil`, and the result is checked rather than assumed.

## c) The incident in the dashboard (1:40 to 2:30)

Open the **Incidents** page. The incident list is cached for up to 10
seconds, so press **R** to rerun if it is not there yet.

Expected:
- The newest incident is selected and shown in the panel below the table:
  the device name, a red `BLOCKED` badge and a `Burst injection` badge.
- The details include the anomaly score against the threshold and the
  action taken (`locked and disabled`).
- **First keystroke to block** shows a figure around a few hundred ms and
  "40 key presses". **First keystroke to lock** is slightly later.
- The **Incidents per day** chart has today's bar.

## d) Ask IncidentRAG about it (2:30 to 3:20)

Open **Ask IncidentRAG** and ask:

```
What should I do about the device that was just blocked?
```

Expected after a few seconds:
- A short answer drawn from the "Responding to a blocked HID injection
  device" playbook: confirm containment, go to the machine, photograph and
  remove the device, and remember the auto-release timer.
- The answer cites its sources as `[1]`, `[2]` and so on.
- The confidence meter is above the threshold line.
- Expanding **Source 1** shows the snippet it came from.

For an answer about this specific incident, go back to the Incidents page
and click **Ask IncidentRAG about this** on the selected incident. The
question is filled in with the incident id.

If the card is amber instead, the gate decided the evidence was too weak,
which is the documented behaviour (see `docs/EVALUATION.md`, section 2).
Rephrase more specifically, for example "How do I respond to a blocked
HID injection device?".

## e) A question outside the corpus is refused (3:20 to 3:40)

Ask:

```
What is the capital of Peru?
```

Expected:
- An amber **Insufficient evidence** card, with confidence close to 0.
- "Not enough evidence in the incident records to answer this reliably."
- A short list of the nearest sources.
- No answer, and no guess.

Say: refusing is the designed, safe outcome. IncidentRAG answers only from
the incident records and playbooks it can cite.

## f) The evasion case, honestly (3:40 to 4:30)

Click into Notepad, then plug in the **randomized** Digispark.

Expected:
- The whole payload, all 137 characters, types out at a human-like pace.
- **Nothing locks.** On the Live status page the device shows `NORMAL`,
  or at most a yellow `SUSPICIOUS` badge for a moment.
- No incident is created.

Say: this payload types at an average speed and spread a person could
produce, and Continuum only sees timing. In simulation it is caught in
about 4 percent of windows. This is the main limitation of a cadence-only
detector; catching it reliably would need signals beyond keystroke timing.

Also point out from part b that even a detected attack lands about 40
keystrokes first. Raw Input lets Continuum see keystrokes, never hold
them back, and it needs 40 presses before it can block anything.

Unplug the randomized board.

## g) Release everything (4:30 to 5:00)

Open a second PowerShell **as Administrator** in the repository folder and
run:

```
.\tasks.ps1 release-all
```

Expected:
- The command prints `Released 1 device(s).`
- In Device Manager the Digispark's down arrow disappears.
- Within about 5 seconds the running runtime notices, and the Live status
  page drops "disabled by Continuum" for that device.

Say: this one command re-enables everything Continuum has disabled,
whatever each device's timer says. Even without it, every device is
released automatically after 10 minutes. The runtime also releases
everything when it starts and when it stops.

## After the demo

```
.\tasks.ps1 stop-all
```

This asks the runtime to stop (it releases any disabled device first) and
closes the API and dashboard windows. The runtime window stays open with
its final log; close it when done.

## If something goes wrong

| Symptom | Fix |
| --- | --- |
| Runtime window says `Elevated: False` and mode `lock_only` | It was not started as Administrator; run `.\tasks.ps1 stop-all`, then `.\tasks.ps1 run-all` and approve the prompt. |
| `run-all` says no trained model | Run `.\tasks.ps1 record-baseline`, then `.\tasks.ps1 train-model`. |
| Dashboard says it cannot reach the connector | The API window closed or failed; check `data\logs\api.log`. |
| IncidentRAG says it could not reach Ollama | Start Ollama (it runs in the system tray) and check `ollama list` shows `llama3.1:8b`. |
| Your own typing got blocked | Unlock, run `.\tasks.ps1 release-all` from an elevated prompt, record another baseline session that includes fast typing, then retrain. |
| The Digispark is not recognised at all | See the driver section in `tools/attacks/README.md`. |
