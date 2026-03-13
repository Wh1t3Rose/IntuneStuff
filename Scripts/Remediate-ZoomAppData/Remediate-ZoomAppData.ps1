<#
.SYNOPSIS
Brief description for Remediate-ZoomAppData.ps1

.DESCRIPTION
Add a longer description for Remediate-ZoomAppData.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Remediate-ZoomAppData.ps1

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

function Remove-ZoomFolder {
    param (
        [string]$path
    )

    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Output "Removed: $path"
        } catch {
            Write-Output "Failed to remove: $path - $_"
        }
    } else {
        Write-Output "Not found: $path"
    }
}

# Remove Zoom folders
Remove-ZoomFolder -path $localZoom
Remove-ZoomFolder -path $roamingZoom

Write-Output "✅ Zoom AppData folders removed."


