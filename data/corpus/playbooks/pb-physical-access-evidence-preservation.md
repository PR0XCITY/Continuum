# Evidence preservation after a physical-access incident

## When to use

Use this playbook whenever a hostile device may have been plugged into
a workstation by someone with physical access. A keystroke injection
incident is also a physical security incident: somebody stood at that
desk or had a device delivered to it. The evidence you preserve in the
first hour decides whether you can later explain what happened, and
whether anyone can be held accountable.

## Steps

1. Secure the area. Ask people not to touch the workstation and note
   who was nearby at the time of the incident.
2. Photograph the workstation, the attached cables and the device in
   place, with a visible clock or timestamp if possible.
3. Wear gloves when you remove the device, since fingerprints on a
   small device may matter later. Place it in an anti-static bag.
4. Label the bag with the date, time, workstation name, your name and
   the Continuum incident id.
5. Start a chain of custody record. Every person who handles the
   device signs and records the time they received it and passed it on.
6. Do not power off the workstation unless it is actively causing
   harm. If you can, capture volatile data first: running processes,
   network connections and signed-in sessions.
7. If a forensic image is listed in recommended_followups
   (capture_forensic_image), image the disk with an approved tool
   before anyone uses the machine again.
8. Export the relevant Windows event logs and the Continuum incident
   record, and store them with the case.
9. Request building access logs and camera footage for the period
   around the incident (review_physical_access_logs). These records are
   often overwritten within days, so ask early.

## Common mistakes

- Plugging the device into a colleague's machine to find out what it
  is. That contaminates evidence and may run the payload again.
- Writing nothing down because "it was only a test device". If it
  turns out not to be, the missing record cannot be recreated.
- Waiting too long to request camera footage and access logs.
- Letting the user keep working on the machine while the investigation
  is still open, which overwrites recent file and log evidence.
