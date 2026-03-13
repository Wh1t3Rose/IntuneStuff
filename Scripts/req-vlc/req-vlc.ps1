<#
.SYNOPSIS
Brief description for req-vlc.ps1

.DESCRIPTION
Add a longer description for req-vlc.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\req-vlc.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-15

Blog: blog.tylercox.tech
#>
# Requirement Script: VLC < 3.0.20.0 (x86/x64)

$MinVersion = [version]"3.0.20.0"
$VLCPaths = @(
    "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe",
    "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"
)

$Result = 0  # Default = does not meet requirement

foreach ($Path in $VLCPaths) {
    if (Test-Path $Path) {
        try {
            $FileVersion = (Get-Item $Path).VersionInfo.FileVersion
            if ($FileVersion) {
                $InstalledVersion = [version]$FileVersion
                if ($InstalledVersion -lt $MinVersion) {
                    $Result = 1
                }
            }
        } catch { }
    }
}

Write-Output $Result



