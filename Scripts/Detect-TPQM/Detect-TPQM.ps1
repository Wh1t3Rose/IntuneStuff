<#
.SYNOPSIS
    Detects if "TrackPoint Quick Menu" (Lenovo) is installed.
.DESCRIPTION
    Searches Appx packages, registry uninstall keys, and winget list.
    Returns exit code 1 if found (non-compliant), 0 if not present.

.NOTES
Author: Tyler Cox
Blog: blog.tylercox.tech
#>

$found = $false

# Check Appx packages (all users)
try {
    $appx = Get-AppxPackage -AllUsers | Where-Object {
        $_.Name -match "TrackPoint" -or $_.PackageFullName -match "TrackPoint"
    }
    if ($appx) { $found = $true }
} catch {}

# Check registry uninstall entries
$hives = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($h in $hives) {
    try {
        $keys = Get-ChildItem -Path $h -ErrorAction SilentlyContinue
        foreach ($k in $keys) {
            $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -and $props.DisplayName -match "TrackPoint Quick Menu") {
                $found = $true
            }
        }
    } catch {}
}

# Check winget list
try {
    $wingetPath = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
    if ($wingetPath) {
        $output = & $wingetPath list --accept-source-agreements 2>$null
        if ($output -match "TrackPoint Quick Menu") { $found = $true }
    }
} catch {}

if ($found) {
    Write-Output "TrackPoint Quick Menu detected."
    exit 1
} else {
    Write-Output "TrackPoint Quick Menu not found."
    exit 0
}

