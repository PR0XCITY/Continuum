# Identifying commands possibly executed after an injection

## When to use

Use this playbook after any blocked or suspicious incident where the
device had time to type before it was stopped, which in practice means
almost every incident. Continuum never records which keys were
pressed, by design, so it cannot tell you what was typed. You have to
reconstruct that from what Windows itself recorded. Work from the
device's first-configured time to the incident's detected_at time,
plus a few minutes of margin either side.

## Steps

1. Fix the time window. Start from the Kernel-PnP configuration event
   for the device and end a few minutes after detected_at.
2. Check the Security event log for process creation events (event id
   4688) in the window. These are only present if process creation
   auditing is enabled, and the full command line is only present if
   the "include command line in process creation events" policy is on.
3. Check Microsoft-Windows-PowerShell/Operational for script block
   events (event id 4104). Injected payloads very often use PowerShell,
   frequently with encoded or hidden window arguments.
4. Read the PowerShell history file for the signed-in user, stored
   under the user's AppData folder in
   Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt.
   It records interactive commands, which is exactly what an injection
   produces.
5. Look at the Run dialog history in the registry under the user's
   Explorer RunMRU key. Many payloads start by opening the Run dialog.
6. Review recently modified files in the user profile, the Recent
   folder, the Startup folder, and the temporary folder for anything
   created inside the window.
7. Check for persistence: new scheduled tasks (TaskScheduler
   operational log), new services, new Run registry values, and new
   local user accounts.
8. If Sysmon is deployed, its process creation and network connection
   events give the most complete picture. Use them first when present.
9. Record every finding, including negative results, in the incident
   notes and the review document.

## Common mistakes

- Concluding nothing ran because event 4688 is missing. The audit
  policy may simply be off. Absence of a log is not absence of
  activity.
- Searching only the administrator account. The payload runs as the
  signed-in user, so check that user's history and profile first.
- Forgetting that a payload can delete its own history file. A
  missing or truncated history file is itself worth noting.
- Running cleanup tools before collecting evidence. Collect first,
  remediate second.
