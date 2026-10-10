# Differentiating a false positive from an attack

## When to use

Use this playbook when someone reports that Continuum blocked a device
that they believe is legitimate, or when an incident looks borderline:
an anomaly score only just above the threshold, a well known device
name, or a user who says they were simply typing fast. Cadence
detection compares timing, not intent, so some legitimate devices and
people will occasionally look machine-like.

## Steps

1. Read the incident's anomaly score relative to its threshold. A
   score several times above the threshold with burst_injection is
   rarely a person. A score just above the threshold deserves a closer
   look.
2. Check the attack pattern label. Burst injection with near constant
   timing is almost never human. Slowed or randomized patterns are
   more ambiguous because they are designed to resemble people.
3. Identify the device type. Gaming keyboards with on-board macros,
   programmable macro pads, barcode scanners and presentation remotes
   all replay stored sequences with machine timing. They are
   legitimate but behave exactly like an injection device.
4. Look at the history. Search earlier incidents for the same device
   id. A device that triggers repeatedly at similar scores during
   normal working hours is more likely a quirky legitimate device.
5. Talk to the user. Ask what they were doing at the detected_at time.
   A fast typist rarely produces long runs of evenly spaced
   keystrokes; a macro key press does.
6. Confirm the device is physically the one the user describes, and
   that it was not swapped or modified.
7. If confirmed legitimate, record "false positive" and the reason in
   the incident notes, then add the device instance id to the
   allowlist following the allowlisting policy.
8. If anything does not add up, treat the incident as an attack.

## Common mistakes

- Accepting "I was just typing fast" without checking the pattern. A
  human cannot sustain burst cadence.
- Allowlisting a device by vendor id because the brand looks familiar.
  Attack tools imitate familiar brands on purpose.
- Lowering the global detection threshold to silence one device. Use
  the allowlist for individual exceptions instead.
- Closing a false positive without writing a note, so the next
  analyst repeats the same investigation.
