<#
.SYNOPSIS
Checks the state of NetBIOS over TCP/IP on the active network adapter.

.DESCRIPTION
Determines the active network adapter, reads the TcpipNetbiosOptions value from
Win32_NetworkAdapterConfiguration, logs the result and returns exit codes:
0 = compliant (NetBIOS disabled), 1 = non-compliant or error.

.NOTES
Author: Tyler Cox
Created: 2025-10-13
Blog: blog.tylercox.tech
#>

# --- Logging setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir   = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$logFile  = Join-Path $logDir "Detect-NetBiosState_$timestamp.log"

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
        # If logging fails, still write to host
    }
    Write-Output $line
}

Write-Log "Starting Detect-NetBiosState."

function Get-ActiveNetworkCard {
    try {
        $nic = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
               Where-Object { $_.Status -eq 'Up' -and $_.ConnectorPresent -eq $true } |
               Select-Object -First 1
        if ($null -ne $nic) {
            Write-Log "Active NIC detected: $($nic.InterfaceDescription)"
            return $nic.InterfaceDescription
        } else {
            Write-Log "No active physical NIC found." "WARN"
            return $null
        }
    } catch {
        Write-Log "Error detecting active NIC: $_" "ERROR"
        return $null
    }
}

function Get-NetBiosState {
    param([string]$AdapterDescription)
    if (-not $AdapterDescription) {
        Write-Log "Get-NetBiosState called with empty adapter description." "ERROR"
        return $null
    }

    try {
        $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
               Where-Object { $_.Description -eq $AdapterDescription } | Select-Object -First 1

        if ($null -eq $cfg) {
            Write-Log "No Win32_NetworkAdapterConfiguration found for '$AdapterDescription'." "WARN"
            return $null
        }

        $raw = $cfg.TcpipNetbiosOptions
    } catch {
        Write-Log "Error querying Win32_NetworkAdapterConfiguration: $_" "ERROR"
        return $null
    }

    switch ($raw) {
        0 { $desc = 'EnableNetbiosViaDhcp' }
        1 { $desc = 'EnableNetbios' }
        2 { $desc = 'DisableNetbios' }
        default { $desc = 'Unknown' }
    }

    Write-Log "NetBIOS raw state: $raw ; description: $desc"
    return [PSCustomObject]@{ State = $raw; Description = $desc }
}

# --- Main ---
$adapter = Get-ActiveNetworkCard
if (-not $adapter) {
    Write-Log "Unable to determine active adapter; treating as non-compliant." "ERROR"
    Write-Log "Detect-NetBiosState finished." "INFO"
    exit 1
}

$nb = Get-NetBiosState -AdapterDescription $adapter
if (-not $nb) {
    Write-Log "Unable to determine NetBIOS state; treating as non-compliant." "ERROR"
    Write-Log "Detect-NetBiosState finished." "INFO"
    exit 1
}

if ($nb.State -eq 2) {
    Write-Log "NetBIOS is disabled (State=2). COMPLIANT." "INFO"
    Write-Log "Detect-NetBiosState finished." "INFO"
    exit 0
} else {
    Write-Log "NetBIOS is NOT disabled (State=$($nb.State) - $($nb.Description)). NON-COMPLIANT." "WARN"
    Write-Log "Detect-NetBiosState finished." "INFO"
    exit 1
}