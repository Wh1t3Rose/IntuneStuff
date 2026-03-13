<#
.SYNOPSIS
Detects and reports network adapters with Idle Power Saving enabled.

.DESCRIPTION
Queries advanced adapter properties for the 'Idle Power Saving' setting and
identifies adapters with the registry value set to '1'. If any adapters are
found, the script writes a message and exits non‑zero to indicate action is
required; otherwise it writes a message and exits zero.

.PARAMETER DisplayName
Name of the advanced adapter property to query. Default: 'Idle Power Saving'.

.EXAMPLE
.\Detect-NetPowerSave.ps1
Runs the detection and exits 0 when no adapters are found with the setting enabled,
or 1 when adapters are found.

.INPUTS
None.

.OUTPUTS
Writes a short status string and exits with code:
0 - no adapters found with Idle Power Saving enabled
1 - one or more adapters found with Idle Power Saving enabled

.NOTES
Author: Tyler Cox
Created: 2025-10-17
Blog: blog.tylercox.tech
#>

# --- Logging setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir   = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$logFile  = Join-Path $logDir "Detect-NetPowerSave_$timestamp.log"

if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    try {
        Add-Content -Path $logFile -Value $line -ErrorAction Stop
    } catch {
        # logging failed — continue but write to host
    }
    Write-Output $line
}

Write-Log "Starting Detect-NetPowerSave."

try {
    $adapters = Get-NetAdapterAdvancedProperty -DisplayName 'Idle Power Saving' -ErrorAction SilentlyContinue |
                Where-Object { $_.RegistryValue -eq '1' -or $_.RegistryValue -eq 1 }

    if ($null -eq $adapters -or $adapters.Count -eq 0) {
        Write-Log 'No adapter(s) found with Idle Power Saving enabled, nothing to do...' 'INFO'
        exit 0
    }
    else {
        Write-Log 'Adapter(s) found with Idle Power Saving enabled:' 'WARN'
        $adapters | ForEach-Object { Write-Log "Adapter: $($_.InstanceId) / $($_.DisplayName) / RegistryValue=$($_.RegistryValue)" 'WARN' }
        Write-Log 'Detection result: NON-COMPLIANT' 'WARN'
        exit 1
    }
}
catch {
    Write-Log "Error while querying adapter advanced properties: $_" 'ERROR'
    # Preserve previous behavior: treat error as no adapters found (pass)
    Write-Log 'Assuming no adapters found due to error; exiting compliant.' 'INFO'
    exit 0
}