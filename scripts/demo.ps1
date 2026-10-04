<#
Public demo in one command: gateway, Streamlit (agent + dashboard) and an ngrok tunnel.

    .\scripts\demo.ps1                       # open link, no login
    .\scripts\demo.ps1 -Password "..."       # login demo/<password> (or set $env:ACL_DEMO_PASSWORD)

The gateway and Streamlit open in their own windows (their logs); ngrok runs here.
Ctrl+C stops the tunnel and both windows. The ngrok authtoken is read from ngrok's own
config (`ngrok config add-authtoken <token>`), never from this repository.
#>
param(
    [string]$Domain = "bottle-mustard-majestic.ngrok-free.dev",
    [string]$User = "demo",
    [string]$Password = $env:ACL_DEMO_PASSWORD,
    [int]$GatewayPort = 8000,
    [int]$UiPort = 8501
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

function Wait-Port([int]$Port, [string]$Name, [int]$Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $client = New-Object Net.Sockets.TcpClient
        try { $client.Connect("127.0.0.1", $Port); return } catch { Start-Sleep -Milliseconds 500 } finally { $client.Dispose() }
    }
    throw "$Name did not start on port $Port within $Seconds s; see its window for the error."
}

function Test-Port([int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try { $client.Connect("127.0.0.1", $Port); return $true } catch { return $false } finally { $client.Dispose() }
}

# --- Preconditions ---------------------------------------------------------
$ngrok = (Get-Command ngrok -ErrorAction SilentlyContinue).Source
if (-not $ngrok) { $ngrok = Join-Path $env:LOCALAPPDATA "ngrok-bin\ngrok.exe" }
if (-not (Test-Path $ngrok)) { throw "ngrok not found. Install it from https://ngrok.com/download and add it to PATH." }
& $ngrok config check | Out-Null
if ($LASTEXITCODE -ne 0) { throw "ngrok config is invalid. Run: ngrok config add-authtoken <token>" }

if ($Password -and $Password.Length -lt 8) { throw "The password must be at least 8 characters (ngrok's rule)." }

function Get-PortCommand([int]$Port) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) { (Get-CimInstance Win32_Process -Filter "ProcessId=$($conn.OwningProcess)").CommandLine }
}

# A gateway that is already running is reused; the UI port must serve app.py (agent + dashboard).
$startGateway = -not (Test-Port $GatewayPort)
if (-not $startGateway) { Write-Host "Gateway already running on port $GatewayPort, reusing it." }
$startUi = -not (Test-Port $UiPort)
if (-not $startUi) {
    $command = Get-PortCommand $UiPort
    if ($command -notmatch "streamlit\s+run\s+app\.py") {
        throw "Port $UiPort is taken by: $command`nStop it (the old separate dashboard?) or pass -UiPort <free port>."
    }
    Write-Host "UI (app.py) already running on port $UiPort, reusing it."
}
if (-not (Test-Port 11434)) { Write-Warning "Ollama is not answering on 127.0.0.1:11434; chat answers will fail until it runs." }
if (-not (Test-Path (Join-Path $root "demo.db"))) {
    Write-Host "demo.db missing, seeding it..."
    & $python (Join-Path $root "db\seed.py")
}

# --- Start ---------------------------------------------------------------
$processes = @()
try {
    if ($startGateway) {
        Write-Host "Starting the gateway on 127.0.0.1:$GatewayPort ..."
        $processes += Start-Process $python -WorkingDirectory $root -PassThru `
            -ArgumentList "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "$GatewayPort"
        Wait-Port $GatewayPort "Gateway"
    }
    if ($startUi) {
        Write-Host "Starting the UI (agent + dashboard) on 127.0.0.1:$UiPort ..."
        $processes += Start-Process $python -WorkingDirectory $root -PassThru `
            -ArgumentList "-m", "streamlit", "run", "app.py", "--server.port", "$UiPort", "--server.address", "127.0.0.1"
        Wait-Port $UiPort "Streamlit"
    }

    Write-Host ""
    $login = if ($Password) { "   (login: $User / your password)" } else { "   (open, no login)" }
    Write-Host "Public URL:  https://$Domain$login" -ForegroundColor Green
    Write-Host "  Agent:     https://$Domain/agent"
    Write-Host "  Dashboard: https://$Domain/dashboard"
    Write-Host "  Inspector: http://127.0.0.1:4040"
    Write-Host "Ctrl+C stops everything."
    Write-Host ""
    $auth = if ($Password) { @("--basic-auth", "${User}:${Password}") } else { @() }
    & $ngrok http $UiPort --url "https://$Domain" @auth
}
finally {
    foreach ($p in $processes) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "Stopped the gateway and the UI."
}
