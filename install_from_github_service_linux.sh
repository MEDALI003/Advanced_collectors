param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("manager","agent")]
    [string]$Role
)

$ErrorActionPreference = "Stop"

$RepoUrl = if ($env:REPO_URL) { $env:REPO_URL } else { "https://github.com/MEDALI003/Advanced_collectors.git" }
$InstallRoot = if ($env:INSTALL_ROOT) { $env:INSTALL_ROOT } else { "C:\AdvancedCollectors" }
$ManagerBranch = if ($env:MANAGER_BRANCH) { $env:MANAGER_BRANCH } else { "manager" }
$AgentBranch = if ($env:AGENT_BRANCH) { $env:AGENT_BRANCH } else { "agent" }

$ManagerHost = if ($env:MANAGER_HOST) { $env:MANAGER_HOST } else { "127.0.0.1" }
$ManagerPort = if ($env:MANAGER_PORT) { $env:MANAGER_PORT } else { "8000" }
$ManagerUrl = if ($env:MANAGER_URL) { $env:MANAGER_URL } else { "http://$ManagerHost`:$ManagerPort/ingest" }

$ApiKey = if ($env:SIEM_API_KEY) { $env:SIEM_API_KEY } else { "strong-api-key" }
$HmacSecret = if ($env:SIEM_HMAC_SECRET) { $env:SIEM_HMAC_SECRET } else { "strong-hmac-secret" }

function Ensure-Admin {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function Clone-Branch([string]$Branch, [string]$Dest) {
    if (-not (Test-Path $Dest)) {
        git clone --branch $Branch $RepoUrl $Dest
    } else {
        Push-Location $Dest
        try {
            git fetch --all
            git checkout $Branch
            git pull
        } finally {
            Pop-Location
        }
    }
}

function Write-AgentConfig([string]$AgentDir) {
    New-Item -ItemType Directory -Force -Path (Join-Path $AgentDir "watchdir") | Out-Null
    $cfg = @{
        manager_url = $ManagerUrl
        api_key = $ApiKey
        hmac_secret = $HmacSecret
        interval_seconds = 30
        watch_directory = "./watchdir"
        log_targets = @{
            linux = @("ssh","cron")
            windows = @("Security","System")
            darwin = @("sshd","sudo")
        }
        watch_services = @{
            linux = @("ssh","cron")
            windows = @("WinDefend","EventLog","Spooler")
            darwin = @("com.openssh.sshd")
        }
        limits = @{
            max_file_scan = 5000
            max_network_connections = 100
            top_processes = 10
        }
        tls_verify = $true
    }
    $cfg | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path (Join-Path $AgentDir "config.json")
}

function Create-StartScript([string]$FilePath, [string]$Content) {
    $Content | Set-Content -Encoding UTF8 -Path $FilePath
}

function Register-StartupTask([string]$TaskName, [string]$ScriptPath) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Install-Manager {
    $Dest = Join-Path $InstallRoot "manager"
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    Clone-Branch $ManagerBranch $Dest

    python -m venv (Join-Path $Dest ".venv")
    & (Join-Path $Dest ".venv\Scripts\python.exe") -m pip install --upgrade pip
    & (Join-Path $Dest ".venv\Scripts\python.exe") -m pip install -r (Join-Path $Dest "requirements.txt")

    @"
`$env:SIEM_API_KEY="$ApiKey"
`$env:SIEM_HMAC_SECRET="$HmacSecret"
Set-Location "$Dest"
& "$Dest\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port $ManagerPort
"@ | Set-Content -Encoding UTF8 -Path (Join-Path $Dest "run_manager.ps1")

    Register-StartupTask -TaskName "AdvancedCollectorsManager" -ScriptPath (Join-Path $Dest "run_manager.ps1")
    Start-ScheduledTask -TaskName "AdvancedCollectorsManager"
    Write-Host "Manager auto-start task created."
}

function Install-Agent {
    $Dest = Join-Path $InstallRoot "agent"
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    Clone-Branch $AgentBranch $Dest

    python -m venv (Join-Path $Dest ".venv")
    & (Join-Path $Dest ".venv\Scripts\python.exe") -m pip install --upgrade pip
    & (Join-Path $Dest ".venv\Scripts\python.exe") -m pip install -r (Join-Path $Dest "requirements.txt")

    Write-AgentConfig $Dest

    @"
Set-Location "$Dest"
& "$Dest\.venv\Scripts\python.exe" "$Dest\agent.py"
"@ | Set-Content -Encoding UTF8 -Path (Join-Path $Dest "run_agent.ps1")

    Register-StartupTask -TaskName "AdvancedCollectorsAgent" -ScriptPath (Join-Path $Dest "run_agent.ps1")
    Start-ScheduledTask -TaskName "AdvancedCollectorsAgent"
    Write-Host "Agent auto-start task created."
    Write-Host "Current manager URL: $ManagerUrl"
    Write-Host "If manager IP changes, rerun with:"
    Write-Host '$env:MANAGER_HOST="NEW_IP"; .\install_from_github_service_windows.ps1 agent'
    Write-Host "Or better, use DNS:"
    Write-Host '$env:MANAGER_URL="http://siem-manager.local:8000/ingest"; .\install_from_github_service_windows.ps1 agent'
}

Ensure-Admin

switch ($Role) {
    "manager" { Install-Manager }
    "agent"   { Install-Agent }
}
