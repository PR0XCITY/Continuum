# Hardening Windows against rogue HID devices

## When to use

Use this playbook when you want to reduce how much a rogue keyboard
can achieve on Windows workstations, independent of detection.
Continuum detects and contains injection after it starts. Hardening
makes it harder for a new device to work at all and limits the damage
if it does. Apply changes through Group Policy so they are consistent
and auditable.

## Steps

1. Open the Group Policy editor and go to Computer Configuration,
   Administrative Templates, System, Device Installation, Device
   Installation Restrictions.
2. Enable "Allow installation of devices that match any of these
   device instance IDs" and list the approved keyboards from your
   allowlist inventory. On older builds, the device ID variant
   matches by hardware id instead and is less precise.
3. Enable "Prevent installation of devices not described by other
   policy settings" so that unknown devices are refused by default.
   On current Windows versions also enable the layered order of
   evaluation policy so that allow and prevent rules combine
   predictably.
4. Test on a pilot machine with a spare keyboard before rolling out.
   A mistake here can leave users with no working input device.
5. Configure the Removable Storage Access policies to deny write or
   execute access to removable drives, since many attack tools also
   expose a storage function.
6. Shorten the screen lock timeout and require Windows key plus L
   habits. An injection device is far less useful against a locked
   session.
7. Remove local administrator rights from everyday accounts. Most
   damaging payloads need elevation.
8. Enable process creation auditing with command lines and PowerShell
   script block logging so that any future incident can be
   investigated.
9. Where practical, block unused external ports physically or in
   firmware settings on shared and kiosk machines.

## Common mistakes

- Enabling the prevent policy before adding allow entries, which locks
  out every new keyboard including replacements for broken ones.
- Forgetting that already installed devices are not affected unless
  the policy is applied to matching installed devices as well.
- Relying on vendor and product id rules alone. They are trivial for
  an attacker to imitate.
- Hardening without logging, so that a successful attack leaves no
  trace to investigate.
