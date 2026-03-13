<#
.SYNOPSIS
Brief description for Detect-ZoomAppData.ps1

.DESCRIPTION
Add a longer description for Detect-ZoomAppData.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Detect-ZoomAppData.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-10-02
Blog: blog.tylercox.tech
#>
# Define Zoom AppData paths
$localZoom = Join-Path $env:LOCALAPPDATA "Zoom"
$roamingZoom = Join-Path $env:APPDATA "Zoom"

# Check if Zoom folders exist separately
$found = $false

if (Test-Path $localZoom) {
    Write-Output "Detected Zoom in LOCALAPPDATA: $localZoom"
    $found = $true
}

if (Test-Path $roamingZoom) {
    Write-Output "Detected Zoom in APPDATA: $roamingZoom"
    $found = $true
}

# Return appropriate exit code
if ($found) {
    exit 1  # Zoom data found → remediation needed
} else {
    Write-Output "No Zoom AppData folders found."
    exit 0  # Zoom data not found
}



