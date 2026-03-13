<#
.SYNOPSIS
Suspends BitLocker protection on a target volume.

.DESCRIPTION
Suspends BitLocker for a specified volume (default C:) and reports status before/after.
Designed for local admin/SYSTEM execution (e.g., Intune remediations, runbooks, packaging tasks).

.PARAMETER MountPoint
Target volume mount point. Default is 'C:'.

.PARAMETER RebootCount
Number of reboots BitLocker stays suspended for. Default is 3.
Use 0 to suspend until manually resumed.

.PARAMETER WhatIf
Simulates the suspend action without making changes.

.EXAMPLE
.\Suspend-BitLocker.ps1

.EXAMPLE
.\Suspend-BitLocker.ps1 -MountPoint 'C:' -RebootCount 2

.NOTES
Author: Tyler Cox
Created: 2026-03-06
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$MountPoint = 'C:',
    [ValidateRange(0, 15)]
    [int]$RebootCount = 2
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Output 'Error: Script must be run as Administrator/SYSTEM.'
    exit 1
}

if (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Write-Output 'Error: BitLocker cmdlets are unavailable on this system.'
    exit 1
}

$volume = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop

Write-Output "Volume: $MountPoint"
Write-Output "ProtectionStatus (before): $($volume.ProtectionStatus)"
Write-Output "LockStatus (before): $($volume.LockStatus)"
Write-Output "VolumeStatus (before): $($volume.VolumeStatus)"

$hasKeyProtectors = @($volume.KeyProtector).Count -gt 0
$isBitLockerEnabled = $hasKeyProtectors -and ($volume.VolumeStatus -ne 'FullyDecrypted')
$isSuspended = ($volume.ProtectionStatus -eq 'Off') -and $isBitLockerEnabled

if (-not $isBitLockerEnabled) {
    Write-Output 'BitLocker protection is already off or not enabled; no suspend action required.'
    exit 0
}

if ($isSuspended) {
    Write-Output 'BitLocker is currently suspended. Resuming first to reset suspension timer.'
    if ($PSCmdlet.ShouldProcess($MountPoint, 'Resume BitLocker before re-suspending')) {
        Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop
        Start-Sleep -Seconds 2
        $volume = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
        Write-Output "ProtectionStatus (after resume): $($volume.ProtectionStatus)"
    }
}

$actionText = if ($RebootCount -eq 0) {
    'Suspend BitLocker until manually resumed'
} else {
    "Suspend BitLocker for $RebootCount reboot(s)"
}

if ($PSCmdlet.ShouldProcess($MountPoint, $actionText)) {
    Suspend-BitLocker -MountPoint $MountPoint -RebootCount $RebootCount -ErrorAction Stop
    Start-Sleep -Seconds 2
}

$after = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
Write-Output "ProtectionStatus (after): $($after.ProtectionStatus)"
Write-Output "AutoUnlockEnabled: $($after.AutoUnlockEnabled)"
Write-Output "KeyProtectorCount: $(@($after.KeyProtector).Count)"

$tagDir = 'C:\ProgramData\VACO\InstalledApps'
$tagPath = Join-Path -Path $tagDir -ChildPath 'Suspend-Bitlocker-2Reboot.tag'

if (-not (Test-Path -Path $tagDir)) {
    New-Item -Path $tagDir -ItemType Directory -Force | Out-Null
}

New-Item -Path $tagPath -ItemType File -Force | Out-Null
Write-Output "Created tag file: $tagPath"

Write-Output 'Done.'

exit 0
