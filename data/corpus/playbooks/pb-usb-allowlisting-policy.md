# USB device allowlisting policy and rollout

## When to use

Use this playbook when you introduce or change the device allowlist,
either in Continuum's own configuration or in Windows device
installation policy. An allowlist states which input devices are
trusted, so that everything else can be treated with suspicion. Done
carelessly it either locks out legitimate users or quietly trusts the
very devices an attacker would imitate.

## Steps

1. Inventory first. For each workstation in scope, record every
   keyboard and keyboard-like device in use: built-in laptop
   keyboards, external keyboards, barcode scanners, macro pads and
   presentation remotes.
2. Identify each device by its Windows device instance id, not just
   by vendor and product id. Vendor and product ids are shared by every
   unit of a model and are easy to forge. The instance id ties the
   entry to one physical port path or serial number.
3. Add the built-in keyboard of every laptop to the Continuum
   allowlist (response.allowlist in config/default.yaml, or
   config/local.yaml for a machine-specific override). Continuum never
   disables an allowlisted device and never disables the last
   remaining keyboard, but listing the built-in keyboard explicitly
   removes any doubt.
4. Roll out in stages. Start with the response mode set to alert_only
   on a pilot group for one to two weeks, review every incident, and
   only then move to lock_and_disable.
5. Write down an exception process: who may request an addition, who
   approves it, and how quickly. Without one, people find their own
   workarounds.
6. Review the allowlist every quarter. Remove devices that have been
   retired, and confirm that each remaining entry still has an owner.
7. Keep a copy of the allowlist under version control with a short
   reason for every entry, so that later reviewers know why it was
   trusted.

## Common mistakes

- Allowlisting by vendor id alone. That trusts every device claiming
  to be from that manufacturer, including attack tools configured to
  imitate it.
- Adding a device to the allowlist in response to an incident before
  confirming the incident was a false positive.
- Skipping the alert_only pilot and discovering on day one that a
  whole department relies on barcode scanners.
- Letting the allowlist grow without review until nobody can say why
  half of the entries exist.
