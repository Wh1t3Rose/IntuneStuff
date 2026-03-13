<#
.SYNOPSIS
Detects whether Microsoft Teams (personal / per-user install) is installed for the current user.

.DESCRIPTION
Checks the typical per-user Teams executable path under %LOCALAPPDATA%\Microsoft\Teams\current\Teams.exe
and also queries Appx packages for a package named "MicrosoftTeams". If either is present the script
indicates that Teams Personal is installed.

.PARAMETER AppPath
Path tested for the Teams desktop executable. Default is "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe".

.EXAMPLE
.\Detect-PersonalTeams.ps1
Runs the detection and exits with code 0 when Teams Personal is not found, or 1 when it is found.

.INPUTS
None.

.OUTPUTS
Writes a short status message to host and exits with code:
0 - PASS (Teams Personal not detected)
1 - FAIL (Teams Personal detected)

.NOTES
Author: Tyler Cox
Created: 2025-09-16
Blog: blog.tylercox.tech
#>
# ...existing code...
$AppPath = "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe"
$Appx = Get-AppxPackage -Name "MicrosoftTeams" -ErrorAction SilentlyContinue

if ((Test-Path $AppPath) -or ($Appx)) {
    Write-Host "Teams Personal is installed — detection fails."
    exit 1  # FAIL
} else {
    Write-Host "Teams Personal is not installed — detection passes."
    exit 0  # PASS
}$AppPath = "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe"
$Appx = Get-AppxPackage -Name "MicrosoftTeams" -ErrorAction SilentlyContinue

if ((Test-Path $AppPath) -or ($Appx)) {
    Write-Host "Teams Personal is installed — detection fails."
    exit 1  # FAIL
} else {
    Write-Host "Teams Personal is not installed — detection passes."
    exit 0  # PASS
}

