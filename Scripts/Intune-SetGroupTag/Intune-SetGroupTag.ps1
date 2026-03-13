<#
.SYNOPSIS
    Bulk updates Windows Autopilot device Group Tags from a CSV file using Microsoft Graph.

.DESCRIPTION
    This script connects to Microsoft Graph and updates the Group Tag property of 
    Windows Autopilot device identities based on serial numbers supplied in a CSV file.

    It will:
      - Read serial numbers from a CSV file (either with or without a header row).
      - Query each serial in Microsoft Intune�s Autopilot device list.
      - Update the GroupTag property for matching devices.
      - Report the number of successful and failed updates.

.PARAMETER CsvPath
    The full path to the CSV file containing serial numbers.  
    Can either be a plain text list or a CSV with a "SerialNumber" column header.

.PARAMETER GroupTag
    The target Group Tag to assign to each device.

.NOTES
Author: Tyler Cox
Created: 2025-10-16
Blog: blog.tylercox.tech
#>

# ========= EDIT THESE TWO VALUES =================================
$CsvPath  = "C:\Temp\file.csv"        # ? your file
$GroupTag = 'Win11-Internal'          # ? target groupTag
# =================================================================

# Ensure the correct Graph module exists
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement.Enrollment)) {
    Write-Host 'Installing Microsoft.Graph.DeviceManagement.Enrollment...'
    Install-Module Microsoft.Graph.DeviceManagement.Enrollment -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph.DeviceManagement.Enrollment

Write-Host 'Connecting to Microsoft Graph...'
Connect-MgGraph                                 # interactive sign-in

# ----- read serials ------------------------------------------------
if (-not (Test-Path $CsvPath)) { throw "File not found: $CsvPath" }
$first = (Get-Content $CsvPath -First 1).Trim()
$Serials = if ($first -eq 'SerialNumber') {
              (Import-Csv $CsvPath).SerialNumber
           } else { Get-Content $CsvPath }

if (-not $Serials) { throw 'No serial numbers found in file.' }

# ----- loop & update ----------------------------------------------
$OK = 0; $Fail = 0
foreach ($s in $Serials) {
    $s = $s.Trim(); if (-not $s) { continue }

    $d = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity `
            -Filter "contains(serialNumber,'$s')" -All |
         Where-Object { $_.serialNumber -eq $s }

    if (-not $d) { Write-Warning "[$s] not found"; $Fail++; continue }

    try {
        Update-MgDeviceManagementWindowsAutopilotDeviceIdentityDeviceProperty `
            -WindowsAutopilotDeviceIdentityId $d.Id `
            -GroupTag $GroupTag
        Write-Host "[$s] groupTag set to '$GroupTag'"
        $OK++
    } catch {
        Write-Warning "[$s] $($_.Exception.Message)"; $Fail++
    }
}

Write-Host "`nFinished - Success: $OK   Failed: $Fail"
Disconnect-MgGraph


