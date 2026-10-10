# Mapping HID injection incidents to MITRE ATT&CK

## When to use

Use this playbook when writing up an incident, reporting to a security
team, or comparing Continuum incidents with alerts from other tools.
Every Continuum incident carries a mitre_technique field, which
defaults to T1200 Hardware Additions. Mapping the follow-on activity
correctly makes the report useful to people who think in ATT&CK terms.

## Steps

1. Start with T1200 Hardware Additions. Introducing a rogue keyboard
   is the initial access technique for every incident Continuum
   detects, regardless of what the payload did afterwards.
2. Add T1059 Command and Scripting Interpreter if the command review
   found evidence that a shell or PowerShell was started during the
   exposure window. Use the PowerShell sub-technique (T1059.001) when
   PowerShell specifically was used.
3. Add T1204 User Execution only if a person was tricked into
   connecting the device, for example by a "found" USB stick or a
   posted parcel. It describes the human step, not the typing.
4. Add T1547 Boot or Logon Autostart Execution or T1053 Scheduled
   Task if persistence was found, and T1105 Ingress Tool Transfer if
   the payload downloaded anything.
5. Add T1091 Replication Through Removable Media only if the same
   device also delivered files through a storage function.
6. Do not tag T1056.001 Keylogging for an injection incident.
   Keylogging is capturing a user's keystrokes; injection is sending
   fake ones. Continuum itself never records keys, and an injection
   tool is the opposite of a keylogger.
7. Record the final list of techniques in the review document, with
   one line of evidence for each.

## Common mistakes

- Tagging only T1200 and stopping there, which hides what the attacker
  actually achieved.
- Adding techniques because they are plausible rather than because
  evidence was found. Every technique needs a supporting observation.
- Confusing injection with keylogging, as described in step 6.
- Changing the mitre_technique of a stored incident without recording
  why. Add your mapping to the notes and the review instead.
