<#
.SYNOPSIS
Intune Win32 detection script for removed LSUClient scheduled task.

.DESCRIPTION
Detects whether scheduled task 'VACO-LSUClient-PatchTuesday' is absent.
Returns success for Intune detection when the task does NOT exist.

.DETECTION LOGIC
- Task missing  -> Exit 0 (Detected/Success)
- Task exists   -> Exit 1 (Not detected)

.NOTES
Author: Tyler Cox
Created: 2026-03-07
#>

$ErrorActionPreference = 'Stop'
$taskName = 'VACO-LSUClient-PatchTuesday'

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($null -eq $task) {
    Write-Output "Detected: task not present ($taskName)."
    exit 0
}

Write-Output "Not detected: task still present ($taskName)."
exit 1
