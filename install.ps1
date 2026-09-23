<#
.SYNOPSIS
    Generates the .env for Kerubiscan with the detected host IP and starts the deployment.
.DESCRIPTION
    This script detects the local IP address on Windows, replaces the __HOST_IP__ placeholder
    in .env.template, creates a new .env file, and optionally runs docker compose up -d --build.
.EXAMPLE
    .\install.ps1
    Runs full setup and launches docker compose.
.EXAMPLE
    .\install.ps1 -EnvOnly
    Only generates the .env file without launching docker compose.
.EXAMPLE
    .\install.ps1 -HostIp "192.168.1.100"
    Forces a specific IP address.
#>

param (
    [switch]$EnvOnly,
    [string]$HostIp = $env:HOST_IP
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location -Path $ScriptDir

$TemplateFile = ".env.template"
$EnvFile = ".env"

# --- 1. Host IP Detection -------------------------------
function Get-HostIp {
    if ([string]::IsNullOrWhiteSpace($HostIp) -eq $false) {
        return $HostIp
    }

    # Try to find the active IPv4 address that has a default gateway
    $netAdapter = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
                  Sort-Object RouteMetric | Select-Object -First 1
    
    if ($netAdapter) {
        $ipInfo = Get-NetIPAddress -InterfaceIndex $netAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ipInfo) {
            return $ipInfo.IPAddress
        }
    }

    # Fallback if no default route is found (e.g., local dev)
    $ipInfo = Test-Connection -ComputerName (hostname) -Count 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPv4Address
    if ($ipInfo) {
        return $ipInfo.IPAddressToString
    }

    Write-Error "ERROR: Could not automatically detect host IP.`nPlease run with: .\install.ps1 -HostIp 'your.ip.address'"
    exit 1
}

$DetectedIp = Get-HostIp
Write-Host ">> Detected Host IP : $DetectedIp" -ForegroundColor Cyan

# --- 2. Generate .env from template -----------------------
if (-not (Test-Path -Path $TemplateFile)) {
    Write-Error "ERROR: $TemplateFile not found in $ScriptDir"
    exit 1
}

$TemplateContent = Get-Content -Path $TemplateFile -Raw
$NewContent = $TemplateContent -replace "__HOST_IP__", $DetectedIp
Set-Content -Path $EnvFile -Value $NewContent -Encoding UTF8

Write-Host ">> Generated $EnvFile with IP $DetectedIp" -ForegroundColor Green

# --- 3. Optional docker-compose launch --------------------------
if ($EnvOnly) {
    Write-Host ">> -EnvOnly requested. Stopping here (Docker Compose not launched)." -ForegroundColor Yellow
    exit 0
}

Write-Host ">> Building & launching containers..." -ForegroundColor Cyan
docker compose up -d --build

Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host "Frontend : http://${DetectedIp}:9443"
Write-Host "Keycloak : http://${DetectedIp}:1990"
Write-Host "API      : http://${DetectedIp}:9445"
