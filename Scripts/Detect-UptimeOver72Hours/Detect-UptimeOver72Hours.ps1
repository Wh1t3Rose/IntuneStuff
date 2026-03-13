<#
.SYNOPSIS
Intune remediation detection script for device uptime threshold.

.DESCRIPTION
Checks device uptime based on last boot time.
If uptime is greater than 72 hours, returns "With Issue" and exits 1.
Otherwise returns "No Issue" and exits 0.

.NOTES
Author: Tyler Cox
Created: 2026-03-07
#>

$ErrorActionPreference = 'Stop'
$thresholdHours = 192

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $lastBoot = [DateTime]$os.LastBootUpTime
    $uptimeHours = ((Get-Date) - $lastBoot).TotalHours

    if ($uptimeHours -gt $thresholdHours) {
        Write-Output "With Issue"
        Write-Output "UptimeHours=$([math]::Round($uptimeHours,2)); ThresholdHours=$thresholdHours; LastBoot=$lastBoot"
        exit 1
    }

    Write-Output "No Issue"
    Write-Output "UptimeHours=$([math]::Round($uptimeHours,2)); ThresholdHours=$thresholdHours; LastBoot=$lastBoot"
    exit 0
}
catch {
    Write-Output "With Issue"
    Write-Output "Failed to determine uptime: $($_.Exception.Message)"
    exit 1
}
