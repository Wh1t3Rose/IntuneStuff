#Requires -Version 5.1
<#
.SYNOPSIS
    Ensures the Balanced power plan is set as active (creates it if missing).

.DESCRIPTION
    This script checks for the presence of the Balanced power plan, recreates it if missing,
    and activates it as the current system power plan.

.NOTES
Author: Tyler Cox
Created: 2025-09-15
Blog: blog.tylercox.tech
#>

# --- Logging Setup ---

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation'
$logFile = Join-Path $logDir "Remediate-PowerPlanBalanced_$timestamp.log"

# Create log directory if missing
$LogDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation"
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}


Start-Transcript -Path $logFile -Append | Out-Null
Write-Host "[Info] Logging started at $(Get-Date) - Log file: $logFile" -ForegroundColor Cyan

try {
    Write-Host "[Info] Checking for existing power plans..." -ForegroundColor Blue
    $schemes = powercfg /L

    # Look for Balanced plan
    $balancedLine = $schemes | Where-Object { $_ -match "Balanced" }
    if ($balancedLine -match '{([0-9a-fA-F-]+)}') {
        $BalancedGuid = $Matches[1]
        Write-Host "[Info] Found Balanced power plan: $BalancedGuid" -ForegroundColor Blue
    }

    # If Balanced not found, recreate it from default
    if (-not $BalancedGuid) {
        Write-Host "[Warn] Balanced power plan not found. Restoring default..." -ForegroundColor Yellow
        $BalancedGuid = "381b4222-f694-41f0-9685-ff5bb260df2e"
        powercfg -duplicatescheme $BalancedGuid | Out-Null
        Write-Host "[Info] Default Balanced plan restored." -ForegroundColor Green
    }

    # Activate Balanced plan
    Write-Host "[Info] Activating Balanced power plan..." -ForegroundColor Blue
    powercfg /setactive $BalancedGuid
    Write-Host "[Success] Balanced power plan set successfully." -ForegroundColor Green

    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Host "[Error] $($_.Exception.Message)" -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}