<#
.SYNOPSIS
    Removes "TrackPoint Quick Menu" (Lenovo) from device.
.DESCRIPTION
    Attempts to remove Appx/msix, registry-based uninstallers, and winget entries.
    Logs results to C:\Windows\Temp\TrackPointQuickMenu_Remediation.log

.NOTES
Author: Tyler Cox
Blog: blog.tylercox.tech
#>

$Log = "C:\Windows\Software\Logs\TrackPointQuickMenu_Remediation.log"
"===== $(Get-Date -Format o) : Starting TrackPoint Quick Menu remediation =====" | Out-File $Log -Append

function Log {
    param([string]$s)
    $s | Out-File -FilePath $Log -Append
    Write-Output $s
}

# Kill running process
try {
    $proc = Get-Process -Name 'TrackPointQuickMenu' -ErrorAction SilentlyContinue
    if ($proc) {
        Log "Stopping TrackPointQuickMenu process..."
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
    }
} catch {}

# Remove Appx (All users + provisioned)
try {
    $appx = Get-AppxPackage -AllUsers | Where-Object { $_.Name -match "TrackPoint" }
    foreach ($p in $appx) {
        Log "Removing Appx package: $($p.PackageFullName)"
        Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
    }

    $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -match "TrackPoint" }
    foreach ($pp in $prov) {
        Log "Removing provisioned package: $($pp.PackageName)"
        Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction SilentlyContinue
    }
} catch {
    Log "Error removing Appx packages: $_"
}

# Remove via winget
try {
    $wingetPath = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
    if ($wingetPath) {
        Log "Attempting winget uninstall..."
        Start-Process -FilePath $wingetPath -ArgumentList "uninstall","Lenovo.TrackPoint-Quick-Menu","--silent","--accept-package-agreements","--accept-source-agreements" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Start-Process -FilePath $wingetPath -ArgumentList "uninstall","TrackPoint Quick Menu","--silent","--accept-package-agreements","--accept-source-agreements" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    }
} catch {
    Log "Error running winget uninstall: $_"
}

# Remove via registry uninstall strings
function Remove-FromRegistry {
    param([string]$match)

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
                if ($props.DisplayName -and $props.DisplayName -match $match) {
                    $uninstall = $props.UninstallString
                    if ($uninstall) {
                        Log "Executing uninstall: $uninstall"
                        Start-Process "cmd.exe" "/c $uninstall /quiet /norestart" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                    }
                }
            }
        } catch {}
    }
}

Remove-FromRegistry "TrackPoint Quick Menu"

# Verify removal
$stillPresent = $false
try {
    $checkAppx = Get-AppxPackage -AllUsers | Where-Object { $_.Name -match "TrackPoint" }
    if ($checkAppx) { $stillPresent = $true }
    $checkReg = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match "TrackPoint Quick Menu" }
    if ($checkReg) { $stillPresent = $true }
} catch {}

if (-not $stillPresent) {
    Log "Remediation successful. TrackPoint Quick Menu removed or not found."
    exit 0
} else {
    Log "Remediation incomplete. TrackPoint Quick Menu may still be present."
    exit 1
}

