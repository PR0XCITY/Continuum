# Optional: start Continuum automatically at logon

Continuum does not start itself. `.\tasks.ps1 run-all` is the supported
way to run it. If you want it running from the moment you log in, Windows
Task Scheduler can start the three components for you. This is optional,
nothing in setup enables it, and it is fully reversible.

Only the runtime needs Administrator rights, so only its task uses **Run
with highest privileges**. A scheduled task can start elevated without a
UAC prompt, which is why this is opt-in: anyone who can edit the task can
run code as Administrator at your next logon. Register it only on a
machine you control, from a folder only you can write to.

## Register the tasks

Run in **PowerShell as Administrator**, from the repository folder, after
`.\tasks.ps1 setup` and `.\tasks.ps1 train-model` have succeeded:

```powershell
$root = (Resolve-Path .).Path
$user = "$env:USERDOMAIN\$env:USERNAME"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)

function New-ContinuumAction([string]$target) {
    New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $root `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$root\tasks.ps1`" $target"
}

$standard = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$elevated = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName 'Continuum API' -Action (New-ContinuumAction 'window-api') `
    -Trigger $trigger -Settings $settings -Principal $standard
Register-ScheduledTask -TaskName 'Continuum Dashboard' -Action (New-ContinuumAction 'window-dashboard') `
    -Trigger $trigger -Settings $settings -Principal $standard
Register-ScheduledTask -TaskName 'Continuum Runtime' -Action (New-ContinuumAction 'window-runtime') `
    -Trigger $trigger -Settings $settings -Principal $elevated
```

Each component then starts in a minimized window at logon and logs to
`data\logs\<component>.log`, exactly as with `run-all`. If the runtime
starts before the API, it queues incidents in its local outbox and sends
them once the API is up. Ollama's installer already starts Ollama at
logon.

The Task Scheduler GUI (`taskschd.msc`) shows the same three tasks under
Task Scheduler Library. The runtime task has **Run with highest
privileges** ticked on its General tab.

## Start, stop, check

```powershell
Start-ScheduledTask -TaskName 'Continuum Runtime'   # start one now, without logging off
.\tasks.ps1 stop-all                                 # asks the runtime to stop cleanly
Stop-ScheduledTask -TaskName 'Continuum API'         # stops a task and its window
Stop-ScheduledTask -TaskName 'Continuum Dashboard'
Get-ScheduledTask -TaskName 'Continuum*' | Format-Table TaskName, State
```

`stop-all` stops the runtime cleanly through its stop-request file, so
every disabled device is released first. Prefer it over
`Stop-ScheduledTask` for the runtime.

## Remove

```powershell
Unregister-ScheduledTask -TaskName 'Continuum Runtime' -Confirm:$false
Unregister-ScheduledTask -TaskName 'Continuum API' -Confirm:$false
Unregister-ScheduledTask -TaskName 'Continuum Dashboard' -Confirm:$false
```
