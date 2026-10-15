<#
.SYNOPSIS
    Continuum task runner. The justfile's recipes call into this script, so
    `just <target>` and `.\tasks.ps1 <target>` always do the same thing.

.USAGE
    .\tasks.ps1 setup             venv, pinned packages, .env with a new token, embedding model
    .\tasks.ps1 test              pytest (all Win32 calls mocked)
    .\tasks.ps1 lint              ruff check
    .\tasks.ps1 record-baseline   record your typing baseline (add a name to record e.g. ASUS_fast)
    .\tasks.ps1 train-model       train and calibrate your model from the baseline
    .\tasks.ps1 run-api           connector API in this window
    .\tasks.ps1 run-dashboard     dashboard in this window
    .\tasks.ps1 run-runtime       HID Firewall in this window (run from an elevated prompt)
    .\tasks.ps1 run-all           API, dashboard and an elevated runtime, each in its own window
    .\tasks.ps1 stop-all          stop all three cleanly (the runtime releases every device first)
    .\tasks.ps1 status            what is running
    .\tasks.ps1 release-all       re-enable every device Continuum disabled (elevated prompt)
    .\tasks.ps1 evaluate          regenerate docs/EVALUATION.md

    If scripts are blocked on this machine, run once:
        Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet(
        'setup', 'test', 'lint', 'record-baseline', 'train-model',
        'run-api', 'run-dashboard', 'run-runtime', 'run-all', 'stop-all', 'status',
        'release-all', 'evaluate',
        'window-api', 'window-dashboard', 'window-runtime'
    )]
    [string]$Task,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest = @()
)

# Not 'Stop': Windows PowerShell 5.1 turns anything a native program writes to
# stderr (pip's retry warnings, Python's logging) into an error record when
# output is redirected, which 'Stop' would treat as fatal. Native commands are
# judged by their exit code instead (Assert-LastExit), and the cmdlets whose
# failure must abort the script pass -ErrorAction Stop explicitly.
$ErrorActionPreference = 'Continue'

$Root = $PSScriptRoot
$VenvPython = Join-Path $Root '.venv\Scripts\python.exe'
$LogDir = Join-Path $Root 'data\logs'
$RunDir = Join-Path $Root 'data\run'
$StopFile = Join-Path $RunDir 'runtime.stop'
$RuntimeArgs = @('-m', 'continuum.runtime')

Set-Location $Root

# --- helpers -------------------------------------------------------------------

function Assert-LastExit([string]$What) {
    if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE." }
}

function Assert-Venv {
    if (-not (Test-Path $VenvPython)) {
        throw "No .venv found. Run '.\tasks.ps1 setup' first."
    }
}

function Assert-Env {
    if (-not (Test-Path (Join-Path $Root '.env'))) {
        throw "No .env found. Run '.\tasks.ps1 setup' first; it creates one with a new API token."
    }
}

function Get-Endpoints {
    # Host and port come from the same settings the runtime and dashboard read
    # (config/default.yaml, config/local.yaml, environment), so they always agree.
    Assert-Venv
    $code = 'from continuum.common.config import get_settings as g; s = g(); ' +
            'print(s.connector.host, s.connector.port, s.dashboard.host, s.dashboard.port)'
    $parts = (& $VenvPython -c $code) -split ' '
    Assert-LastExit 'Reading the configuration'
    return @{ ApiHost = $parts[0]; ApiPort = $parts[1]; DashHost = $parts[2]; DashPort = $parts[3] }
}

function Get-ApiArgs {
    $e = Get-Endpoints
    return @('-m', 'uvicorn', 'continuum.connector.app:app', '--host', $e.ApiHost, '--port', $e.ApiPort)
}

function Get-DashboardArgs {
    $e = Get-Endpoints
    return @(
        '-m', 'streamlit', 'run', (Join-Path $Root 'src\continuum\dashboard\app.py'),
        '--browser.gatherUsageStats', 'false',
        '--server.address', $e.DashHost, '--server.port', $e.DashPort
    )
}

function Invoke-Python([string[]]$Arguments) {
    Assert-Venv
    & $VenvPython @Arguments
    Assert-LastExit "python $($Arguments -join ' ')"
}

function Find-Python312 {
    # CONTINUUM_PYTHON may point at any python.exe 3.12, for example a conda environment.
    $candidates = @()
    if ($env:CONTINUUM_PYTHON) { $candidates += , @($env:CONTINUUM_PYTHON) }
    $candidates += , @('py', '-3.12')
    $candidates += , @('python')
    foreach ($candidate in $candidates) {
        $exe = $candidate[0]
        $extra = @($candidate | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $version = & $exe @extra -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $version -eq '3.12') { return , $candidate }
    }
    throw ("Python 3.12 was not found. Install it from python.org (Windows installer, 64-bit) " +
           "and rerun, or set CONTINUUM_PYTHON to the full path of a Python 3.12 python.exe.")
}

function New-ApiToken {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Test-Running([string]$Name) {
    $pidFile = Join-Path $RunDir "$Name.pid"
    if (-not (Test-Path $pidFile)) { return $false }
    $processId = [int](Get-Content $pidFile -Raw)
    return [bool](Get-Process -Id $processId -ErrorAction SilentlyContinue)
}

function Start-ComponentWindow([string]$Name, [switch]$Elevated) {
    $arguments = @(
        '-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', (Join-Path $Root 'tasks.ps1'), "window-$Name"
    )
    $options = @{
        FilePath = 'powershell.exe'; ArgumentList = $arguments; PassThru = $true; ErrorAction = 'Stop'
    }
    if ($Elevated) { $options['Verb'] = 'RunAs' }
    $process = Start-Process @options
    Set-Content -Path (Join-Path $RunDir "$Name.pid") -Value $process.Id -Encoding ascii
    return $process
}

function Invoke-Logged([string]$Name, [string[]]$Arguments) {
    # Shows the component's output in its own window and appends it to data\logs\<name>.log.
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $log = Join-Path $LogDir "$Name.log"
    $Host.UI.RawUI.WindowTitle = "Continuum $Name"
    $env:PYTHONUNBUFFERED = '1'
    $banner = "==== $(Get-Date -Format s) starting $Name ===="
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "Log file: $log"
    Add-Content -Path $log -Value $banner -Encoding utf8
    # Python writes its logs to stderr; merge it without PowerShell's error formatting.
    & $VenvPython @Arguments 2>&1 | ForEach-Object {
        $line = "$_"
        Write-Host $line
        Add-Content -Path $log -Value $line -Encoding utf8
    }
    Write-Host "==== $Name exited with code $LASTEXITCODE ====" -ForegroundColor Cyan
}

# --- targets -------------------------------------------------------------------

function Invoke-Setup {
    if (-not (Test-Path $VenvPython)) {
        $python = Find-Python312
        $exe = $python[0]
        $extra = @($python | Select-Object -Skip 1)
        Write-Host "Creating .venv with $($python -join ' ')"
        & $exe @extra -m venv (Join-Path $Root '.venv')
        Assert-LastExit 'Creating the virtual environment'
    }
    & $VenvPython -m pip install --upgrade pip
    Assert-LastExit 'Upgrading pip'
    & $VenvPython -m pip install -e "$Root[dev]"
    Assert-LastExit 'Installing Continuum and its pinned dependencies'

    $envFile = Join-Path $Root '.env'
    if (Test-Path $envFile) {
        Write-Host '.env already exists; left unchanged.'
    }
    else {
        $example = Get-Content (Join-Path $Root '.env.example') -Raw -ErrorAction Stop
        $content = $example.Replace('change-me-to-a-long-random-token', (New-ApiToken))
        Set-Content -Path $envFile -Value $content -Encoding ascii -NoNewline -ErrorAction Stop
        Write-Host 'Created .env with a new random API token.'
    }

    Write-Host 'Downloading the embedding model (once; later runs work offline)...'
    & $VenvPython -m continuum.rag.embed
    Assert-LastExit 'Downloading the embedding model'

    # Prints the provider and model, and only whether a Groq key is set, never the key.
    $code = 'import os; from continuum.common.config import get_settings as g; r = g().rag; ' +
            'print(r.llm_provider, r.groq_model if r.llm_provider == "groq" else r.ollama_model, ' +
            'bool(os.environ.get(r.groq_api_key_env_var)))'
    $provider, $model, $hasKey = (& $VenvPython -c $code) -split ' '
    if ($provider -eq 'groq') {
        if ($hasKey -eq 'True') {
            Write-Host "IncidentRAG will use Groq ($model); the API key is set."
        }
        else {
            Write-Host ('IncidentRAG uses Groq, but GROQ_API_KEY in .env is empty. Create a key at ' +
                        'https://console.groq.com/keys and paste it into .env.') -ForegroundColor Yellow
        }
    }
    elseif (Get-Command ollama -ErrorAction SilentlyContinue) {
        $installed = (& ollama list 2>$null) -join "`n"
        if ($installed -match [regex]::Escape($model)) {
            Write-Host "Ollama model $model is installed."
        }
        else {
            Write-Host "Ollama is installed but $model is not. Run: ollama pull $model" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Ollama was not found. Install it from ollama.com, then run: ollama pull $model" -ForegroundColor Yellow
    }
    Write-Host 'Setup complete. Next: .\tasks.ps1 record-baseline, then .\tasks.ps1 train-model.' -ForegroundColor Green
}

function Invoke-RunAll {
    Assert-Venv
    Assert-Env
    New-Item -ItemType Directory -Force -Path $LogDir, $RunDir | Out-Null

    foreach ($name in 'api', 'dashboard') {
        if (Test-Running $name) { Write-Host "$name is already running."; continue }
        Start-ComponentWindow $name | Out-Null
        Write-Host "Started $name in its own window."
    }

    $hasModel = & $VenvPython -c "import getpass; from continuum.detection.model import model_path; print(model_path(getpass.getuser()).exists())"
    if (Test-Running 'runtime') {
        Write-Host 'runtime is already running.'
    }
    else {
        if ($hasModel -ne 'True') {
            Write-Host ('No trained model yet: the runtime starts in recording-only mode. Open the ' +
                        "dashboard's Train page to record your typing and train one.") -ForegroundColor Yellow
        }
        Write-Host 'Starting the runtime elevated: approve the Windows prompt (UAC).'
        try {
            Start-ComponentWindow 'runtime' -Elevated | Out-Null
            Write-Host 'Started runtime in its own elevated window.'
        }
        catch {
            Write-Host 'The elevation prompt was declined; the runtime was not started.' -ForegroundColor Yellow
        }
    }

    $e = Get-Endpoints
    Write-Host ''
    Write-Host "API docs:   http://$($e.ApiHost):$($e.ApiPort)/docs"
    Write-Host "Dashboard:  http://$($e.DashHost):$($e.DashPort)"
    Write-Host "Logs:       $LogDir"
    Write-Host 'Stop everything with: .\tasks.ps1 stop-all'
}

function Invoke-StopAll {
    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

    if (Test-Running 'runtime') {
        Write-Host 'Asking the runtime to stop (it releases every disabled device first)...'
        Set-Content -Path $StopFile -Value '' -Encoding ascii
        $deadline = (Get-Date).AddSeconds(20)
        while ((Test-Path $StopFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if (Test-Path $StopFile) {
            Remove-Item $StopFile -Force
            Write-Host 'The runtime did not respond. Press Ctrl+C in its window to stop it.' -ForegroundColor Yellow
        }
        else {
            Write-Host 'Runtime stopped. Its window stays open with the final log; close it when done.'
        }
    }
    Remove-Item (Join-Path $RunDir 'runtime.pid') -Force -ErrorAction SilentlyContinue

    foreach ($name in 'dashboard', 'api') {
        $pidFile = Join-Path $RunDir "$name.pid"
        if (Test-Running $name) {
            $processId = [int](Get-Content $pidFile -Raw)
            & taskkill.exe /PID $processId /T /F | Out-Null
            Write-Host "Stopped $name."
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Status {
    foreach ($name in 'api', 'dashboard', 'runtime') {
        $state = if (Test-Running $name) { 'running' } else { 'not running' }
        Write-Host ('{0,-10} {1}' -f $name, $state)
    }
    $e = Get-Endpoints
    $apiUrl = "http://$($e.ApiHost):$($e.ApiPort)"
    try {
        Invoke-RestMethod "$apiUrl/health" -TimeoutSec 2 | Out-Null
        Write-Host "API health: ok ($apiUrl)"
    }
    catch {
        Write-Host 'API health: unreachable'
    }
}

switch ($Task) {
    'setup'            { Invoke-Setup }
    'test'             { Invoke-Python @('-m', 'pytest') }
    'lint'             { Invoke-Python @('-m', 'ruff', 'check', '.') }
    'record-baseline'  { Invoke-Python (@('tools\record_baseline.py') + $Rest) }
    'train-model'      { Invoke-Python (@('tools\train_model.py') + $Rest) }
    'run-api'          { Invoke-Logged 'api' (Get-ApiArgs) }
    'run-dashboard'    { Invoke-Logged 'dashboard' (Get-DashboardArgs) }
    'run-runtime'      {
        Assert-Venv
        Write-Host 'The runtime needs an elevated (Administrator) prompt to disable devices.'
        Invoke-Logged 'runtime' $RuntimeArgs
    }
    'run-all'          { Invoke-RunAll }
    'stop-all'         { Invoke-StopAll }
    'status'           { Invoke-Status }
    'release-all'      { Invoke-Python @('-m', 'continuum.runtime', '--release-all') }
    'evaluate'         { Invoke-Python (@('tools\evaluate_all.py') + $Rest) }
    'window-api'       { Invoke-Logged 'api' (Get-ApiArgs) }
    'window-dashboard' { Invoke-Logged 'dashboard' (Get-DashboardArgs) }
    'window-runtime'   {
        Invoke-Logged 'runtime' $RuntimeArgs
        Remove-Item (Join-Path $RunDir 'runtime.pid') -Force -ErrorAction SilentlyContinue
    }
}
