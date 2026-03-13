<#
.SYNOPSIS
Removes the scheduled task named VACO-LSUClient-PatchTuesday.


.PARAMETER TaskName
Scheduled task name to remove. Default is 'VACO-LSUClient-PatchTuesday'.

.NOTES
Author: Tyler Cox
Created: 2026-03-07
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TaskName = 'VACO-LSUClient-PatchTuesday'
)

$ErrorActionPreference = 'Stop'

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Output "Task not found: $TaskName"
    exit 0
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Output "Removed scheduled task: $TaskName"
}

$tagDir = 'C:\ProgramData\VACO\InstalledApps'
$tagPath = Join-Path -Path $tagDir -ChildPath 'Remove-LSUClientTask.tag'

New-Item -Path $tagPath -ItemType File -Force | Out-Null
Write-Output "Created tag file: $tagPath"

exit 0
