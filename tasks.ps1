<#
.SYNOPSIS
    Continuum task runner for machines without `just` installed.
    Mirrors the justfile targets exactly; keep the two in sync.

.USAGE
    .\tasks.ps1 setup
    .\tasks.ps1 test
    .\tasks.ps1 lint
    .\tasks.ps1 run-runtime
    .\tasks.ps1 run-api
    .\tasks.ps1 run-dashboard
    .\tasks.ps1 run-all
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('setup', 'test', 'lint', 'run-runtime', 'run-api', 'run-dashboard', 'run-all')]
    [string]$Task
)

$ErrorActionPreference = 'Stop'

$VenvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

function Invoke-Setup {
    py -3.12 -m venv (Join-Path $PSScriptRoot '.venv')
    & $VenvPython -m pip install --upgrade pip
    & $VenvPython -m pip install -e "$PSScriptRoot[dev]"
}

function Invoke-Test {
    & $VenvPython -m pytest
}

function Invoke-Lint {
    & $VenvPython -m ruff check .
}

function Invoke-RunRuntime {
    Write-Host "run-runtime needs an elevated PowerShell session for pnputil."
    & $VenvPython -m continuum.runtime
}

function Invoke-RunApi {
    & $VenvPython -m uvicorn continuum.connector.app:app --host 127.0.0.1 --port 8731
}

function Invoke-RunDashboard {
    & $VenvPython -m streamlit run (Join-Path $PSScriptRoot 'src\continuum\dashboard\app.py')
}

function Invoke-RunAll {
    # Runtime is elevated and run separately with ".\tasks.ps1 run-runtime".
    Start-Process powershell -ArgumentList '-NoExit', '-Command', "$PSScriptRoot\tasks.ps1 run-api"
    Start-Process powershell -ArgumentList '-NoExit', '-Command', "$PSScriptRoot\tasks.ps1 run-dashboard"
}

switch ($Task) {
    'setup'         { Invoke-Setup }
    'test'          { Invoke-Test }
    'lint'          { Invoke-Lint }
    'run-runtime'   { Invoke-RunRuntime }
    'run-api'       { Invoke-RunApi }
    'run-dashboard' { Invoke-RunDashboard }
    'run-all'       { Invoke-RunAll }
}
