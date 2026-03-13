<#
.SYNOPSIS
Brief description for REQ-WinRar.ps1

.DESCRIPTION
Add a longer description for REQ-WinRar.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\REQ-WinRar.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-15

Blog: blog.tylercox.tech
#>
# Intune Requirement Script: Output string if WinRAR is installed

$winRarPaths = @(
    "$env:ProgramFiles\WinRAR\WinRAR.exe",
    "$env:ProgramFiles(x86)\WinRAR\WinRAR.exe"
)

foreach ($path in $winRarPaths) {
    if (Test-Path -Path $path) {
        Write-Output "WinRARDetected"
        return
    }
}

Write-Output "WinRARNotDetected"


