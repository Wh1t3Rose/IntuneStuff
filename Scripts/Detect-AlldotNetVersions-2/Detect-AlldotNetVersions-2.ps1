<#
.SYNOPSIS
Detects the installed .NET Framework 4.5+ version on the local machine.

.DESCRIPTION
Reads the Release DWORD from:
HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
Maps the Release value to a human-readable .NET Framework version.
Logs the output to both console and a persistent log file.

.EXAMPLE
.\Detect-AlldotNetVersions-2.ps1

.NOTES
Author: Tyler Cox
Created: 2025-09-15
Blog: blog.tylercox.tech
#>

# -------------------------------
# Logging Setup
# -------------------------------
$LogDirectory = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation"
$LogFile = Join-Path $LogDirectory "Detect-AlldotNetVersions.log"

# Ensure log directory exists
try {
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
        Write-Host "[INFO] Created log directory: $LogDirectory" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "[ERROR] Failed to create log directory: $_" -ForegroundColor Red
    exit 1
}

# Helper function: write to console + log
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $formatted = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "INFO"  { Write-Host $formatted -ForegroundColor Cyan }
        "WARN"  { Write-Host $formatted -ForegroundColor Yellow }
        "ERROR" { Write-Host $formatted -ForegroundColor Red }
    }

    Add-Content -Path $LogFile -Value $formatted
}

# -------------------------------
# Detection Logic
# -------------------------------
try {
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    Write-Log "Checking installed .NET Framework version at: $RegistryPath"

    $release = Get-ItemPropertyValue -LiteralPath $RegistryPath -Name Release -ErrorAction Stop

    switch ($release) {
        { $_ -ge 533320 } { $version = '4.8.1 or later'; break }
        { $_ -ge 528040 } { $version = '4.8'; break }
        { $_ -ge 461808 } { $version = '4.7.2'; break }
        { $_ -ge 461308 } { $version = '4.7.1'; break }
        { $_ -ge 460798 } { $version = '4.7'; break }
        { $_ -ge 394802 } { $version = '4.6.2'; break }
        { $_ -ge 394254 } { $version = '4.6.1'; break }
        { $_ -ge 393295 } { $version = '4.6'; break }
        { $_ -ge 379893 } { $version = '4.5.2'; break }
        { $_ -ge 378675 } { $version = '4.5.1'; break }
        { $_ -ge 378389 } { $version = '4.5'; break }
        default { $version = $null; break }
    }

    if ($version) {
        Write-Log ".NET Framework Version Detected: $version"
        Write-Host ".NET Framework Version Detected: $version" -ForegroundColor Green
    }
    else {
        Write-Log ".NET Framework Version 4.5 or later is not detected." "WARN"
        Write-Host ".NET Framework Version 4.5 or later is not detected." -ForegroundColor Yellow
    }

    # Final log path message
    Write-Host "`nLog file saved at: $LogFile`n" -ForegroundColor Cyan
}
catch {
    Write-Log "Error detecting .NET Framework version: $_" "ERROR"
    Write-Host "Error detecting .NET Framework version: $_" -ForegroundColor Red
    Write-Host "`nLog file saved at: $LogFile`n" -ForegroundColor Cyan
    exit 1
}

# Exit codes for Intune
if ($version) { exit 0 } else { exit 1 }
