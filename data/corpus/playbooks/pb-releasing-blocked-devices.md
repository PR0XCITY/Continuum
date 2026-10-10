# Releasing blocked devices and the auto-release safety rail

## When to use

Use this playbook when a device that Continuum disabled needs to work
again: a confirmed false positive, a device that has been examined and
cleared, or an emergency where a user has lost the ability to type.
Continuum has three ways to re-enable devices, and choosing the right
one avoids both unnecessary lockouts and accidental re-exposure.

## Steps

1. Confirm the device should be released. For a confirmed attack the
   right answer is to physically remove the device, not to re-enable
   it.
2. For a single device, use the connector: POST
   /devices/{device_id}/unblock with a valid bearer token. This queues
   an unblock command in the connector database. The runtime polls
   that table and re-enables the device within a few seconds.
3. If you can wait, do nothing. Every disabled device is released
   automatically after auto_release_timeout_seconds, which is 600
   seconds by default. This rail exists so that a mistake can never
   cause a permanent lockout.
4. In an emergency, release everything at once from an elevated
   prompt with: python -m continuum.runtime --release-all. This
   re-enables every device listed in data/disabled_devices.json,
   regardless of individual timers.
5. After any release, check the live view to confirm the device is
   active again, and add a note to the incident explaining who
   released it and why.
6. If the device was a false positive, add it to the allowlist so it
   is not blocked again on the next keystroke burst.

## Built-in safety rules

Continuum refuses to disable the last remaining keyboard on a machine,
refuses to disable any allowlisted device, and by default refuses to
disable non-USB keyboards such as a laptop's internal PS2 keyboard.
These rules are checked before any pnputil call is made.

## Common mistakes

- Releasing a device that is still attached and hostile. The device
  will simply start typing again.
- Raising auto_release_timeout_seconds to a very large value to keep
  attackers out. Physical removal is the real fix; the timer is a
  safety net against lockouts.
- Running the release-all command without elevation, which cannot
  re-enable devices.
- Forgetting to note the release in the incident, leaving the record
  saying the device is still disabled.
