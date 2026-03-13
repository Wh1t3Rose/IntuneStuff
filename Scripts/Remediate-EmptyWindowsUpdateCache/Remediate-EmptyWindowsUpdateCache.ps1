#Requires -Version 5.1
<#
.SYNOPSIS
    Clears the Windows Update cache to free up disk space.

.DESCRIPTION
    This script stops the Windows Update service, deletes all files within the 
    SoftwareDistribution\Download directory, and then restarts the service.
    It measures free disk space before and after cleanup to show the total space reclaimed.

.NOTES
Author: Tyler Cox
Created: 2025-10-21
Blog: blog.tylercox.tech
#>

# --- Logging Setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation'
$logFile = Join-Path $logDir "Clear-WindowsUpdateCache_$timestamp.log"

# Create log directory if missing
$LogDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation"
if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

Start-Transcript -Path $logFile -Append | Out-Null
Write-Host "[Info] Logging started at $(Get-Date) - Log file: $logFile" -ForegroundColor Cyan

# --- Function: Get-FreeDiskSpace ---
function Get-FreeDiskSpace {
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    $Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($OS.SystemDrive)'" |
        Select-Object @{Name="FreeGB";Expression={[math]::Round($_.FreeSpace / 1GB, 2)}}
    return $Disk.FreeGB
}

try {
    # --- Measure free disk space before cleanup ---
    $Before = Get-FreeDiskSpace
    Write-Host "[Info] Free Disk Space before: $Before GB" -ForegroundColor Blue

    # --- Check Windows Update Service status ---
    $WUService = Get-Service wuauserv -ErrorAction Stop

    # --- Stop Windows Update Service ---
    if ($WUService.Status -eq "Running") {
        Write-Host "[Info] Stopping Windows Update Service..." -ForegroundColor Blue
        Stop-Service -Name "wuauserv" -Force -ErrorAction Stop
    }
    else {
        Write-Host "[Info] Windows Update Service already stopped." -ForegroundColor Yellow
    }

    # --- Clean Windows Update Cache ---
    $UpdateCachePath = Join-Path $env:windir "SoftwareDistribution\Download"
    if (Test-Path $UpdateCachePath) {
        Write-Host "[Info] Cleaning Windows Update Cache at: $UpdateCachePath" -ForegroundColor Blue
        Get-ChildItem -Path $UpdateCachePath -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "[Warn] Windows Update cache path not found: $UpdateCachePath" -ForegroundColor Yellow
    }

    # --- Restart Windows Update Service ---
    Write-Host "[Info] Starting Windows Update Service..." -ForegroundColor Blue
    Start-Service -Name "wuauserv" -ErrorAction Stop

    # --- Measure free disk space after cleanup ---
    $After = Get-FreeDiskSpace
    Write-Host "[Info] Free Disk Space after: $After GB" -ForegroundColor Blue

    # --- Calculate reclaimed space ---
    $Cleaned = [math]::Round(($After - $Before), 2)
    if ($Cleaned -ge 0) {
        Write-Host "[Success] Cleaned: $Cleaned GB reclaimed." -ForegroundColor Green
    }
    else {
        Write-Host "[Warn] No additional free space detected after cleanup." -ForegroundColor Yellow
    }

    Write-Host "[Info] Windows Update cache cleanup completed successfully." -ForegroundColor Green
}
catch {
    Write-Host "[Error] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Stop-Transcript | Out-Null
}
