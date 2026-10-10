# Responding to a blocked HID injection device

## When to use

Use this playbook as soon as Continuum raises an incident with verdict
"blocked", meaning the HID Firewall judged a keyboard-like device to be
typing with machine cadence and acted on it. By the time you read the
incident, the response layer has already done its part: depending on
the configured response mode, the workstation is locked, the offending
device is disabled with pnputil, or both. Your job is to confirm the
containment held, understand what happened, and decide what comes next.

## Steps

1. Open the incident record from the dashboard or with GET
   /incidents/{incident_id}. Note the device name, vendor id, product
   id, attack pattern, anomaly score, threshold and time to detect.
2. Confirm containment. Check the live view (GET /live) and the
   action_taken field. A value of locked_and_disabled means both
   safety actions ran. A value of alert_only means nothing was blocked
   and you must treat the device as still active.
3. Go to the workstation in person. Do not unlock it remotely before
   you have looked at what is plugged into it.
4. Photograph the USB ports and the device before touching anything,
   then unplug the device and bag it. See the evidence preservation
   playbook for labelling and custody.
5. Remember that Continuum auto-releases a disabled device after the
   configured timeout (600 seconds by default). If the device is still
   plugged in when the timer expires, it becomes active again. Removing
   it physically is what makes containment permanent.
6. Estimate the exposure window. Keystrokes typed before detection may
   have executed. The time_to_detect_ms field tells you roughly how
   long the device typed freely. Follow the post-injection command
   review playbook for anything above a few hundred milliseconds.
7. Decide on follow-ups using the incident's recommended_followups
   list as a starting point, for example rotate_credentials when the
   signed-in user had administrative rights.
8. Record your findings in the incident notes field and open a
   post-incident review if the device was confirmed hostile.

## Common mistakes

- Unlocking the workstation and continuing to work with the device
  still attached. Once the auto-release timer fires, the device can
  type again.
- Treating a short time to detect as proof that nothing ran. Even a
  few hundred milliseconds is enough for a short command to be typed
  into an already focused window.
- Plugging the suspicious device into another computer to see what it
  is. That repeats the attack on a second machine. Examine unknown
  hardware only on an isolated analysis system.
- Disabling detection or switching the whole machine to alert_only
  mode because a single incident was inconvenient.
