<#
.SYNOPSIS
    Hardens and remediates the Lenovo TPQM folder by killing related processes,
    removing old files, and reapplying secure permissions.

.DESCRIPTION
    This script is designed to remove, rebuild, and harden the Lenovo TPQM folder
    (C:\Program Files (x86)\Lenovo\TPQM). It stops related processes and services,
    attempts uninstallation if applicable, deletes and recreates the folder,
    and applies restrictive ACLs to prevent SYSTEM from writing to it.
    
    Intended to run under SYSTEM context (e.g., via Intune remediation or scheduled task).
    All activity is logged to C:\ProgramData\IntuneLogs\TPQM_Remediation.log.

.PARAMETER None
    The script takes no parameters.

.NOTES
    Author: Tyler Cox
    Version: 1.0
    Date: October 20, 2025

.CHANGELOG
    v1.0 (2025-10-23)
        - Initial release
        - Added process and service termination for TPQM components
        - Implemented uninstall attempt via Win32_Product
        - Folder removal and recreation logic with fallback using takeown/icacls
        - Hardened ACLs (deny SYSTEM write, restrict inheritance)
        - Logging to C:\ProgramData\IntuneLogs\TPQM_Remediation.log
        - Added optional read-only visual flag on folder
#>

# --- Script Start ---

# Remediate.ps1 - Harden TPQM folder: kill process, remove, recreate, deny SYSTEM write
# Intended to run as SYSTEM (e.g., Intune remediation context)

$logDir = "C:\ProgramData\IntuneLogs"
$logFile = Join-Path $logDir "TPQM_Remediation.log"

# Ensure log folder exists immediately
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-Log { 
    param($m) 
    Add-Content -Path $logFile -Value ("[{0}] {1}" -f (Get-Date -Format s), $m) 
    Write-Output $m
}

Write-Log "=== TPQM Remediation started ==="


$folderPath = "C:\Program Files (x86)\Lenovo\TPQM"
$processNames = @("TPQMAssistant", "TPQM", "TrackPoint", "TPQMAssistant.exe")
$serviceName = "TPQMAssistantService"  # best-effort
Write-Output "=== TPQM Hardening Script Started: $(Get-Date) ==="

# 1) Kill TPQM-related processes
foreach ($proc in $processNames) {
    try {
        $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($found) {
            $found | ForEach-Object {
                Write-Output "Stopping process $($_.Name) (Id $($_.Id))"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Output "No process named $proc found."
        }

        if ($proc -eq "TPQMAssistant") {
            Write-Output "Ensuring TPQMAssistant is terminated..."
            Stop-Process -Name "TPQMAssistant" -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Output "Error stopping process ${proc}: $_"
    }
}

Start-Sleep -Milliseconds 300

# 2) Stop & delete possible service (best-effort)
try {
    Write-Output "Attempting to stop & delete service: $serviceName"
    sc.exe stop $serviceName 2>$null | Out-Null
    sc.exe delete $serviceName 2>$null | Out-Null
    Write-Output "Service stop/delete attempted."
} catch {
    Write-Output "Service removal attempt failed or not present: $_"
}

Start-Sleep -Milliseconds 300

# 3) Uninstall via MSI if present (best-effort)
try {
    $apps = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "TPQM|TrackPoint|Quick Menu" }
    if ($apps) {
        foreach ($app in $apps) {
            try {
                Write-Output "Attempting uninstall of: $($app.Name)"
                $app.Uninstall() | Out-Null
                Write-Output "Uninstalled: $($app.Name)"
            } catch {
                Write-Output "Uninstall failed for $($app.Name): $_"
            }
        }
    } else {
        Write-Output "No Win32_Product entries matching TPQM/TrackPoint/Quick Menu."
    }
} catch {
    Write-Output "Win32_Product enumeration failed or not available: $_"
}

Start-Sleep -Milliseconds 300

# 4) Remove the TPQM folder recursively if present
if (Test-Path $folderPath) {
    try {
        Write-Output "Removing folder: $folderPath (removing read-only attributes first)"
        Get-ChildItem -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    if ($_.Attributes -band [IO.FileAttributes]::ReadOnly) {
                        $_.Attributes = $_.Attributes -bxor [IO.FileAttributes]::ReadOnly
                    }
                } catch {}
            }

        Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400

        if (Test-Path $folderPath) {
            Write-Output "Folder still exists after initial Remove-Item. Attempting takeown & icacls fallback."
            try {
                takeown.exe /f $folderPath /r /d y 2>$null | Out-Null
                icacls.exe $folderPath /grant "Administrators:(OI)(CI)F" /t 2>$null | Out-Null
                Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Output "Fallback delete attempt failed: $_"
            }
        } else {
            Write-Output "Folder removed successfully."
        }
    } catch {
        Write-Output "Failed to remove folder: $_"
    }
} else {
    Write-Output "Folder not present: $folderPath"
}

Start-Sleep -Milliseconds 300

# 5) Recreate the folder
try {
    if (-not (Test-Path $folderPath)) {
        Write-Output "Creating folder: $folderPath"
        New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
        Start-Sleep -Milliseconds 200
    } else {
        Write-Output "Folder already present, proceeding to ACL changes."
    }
} catch {
    Write-Output "Failed to create folder: $_"
}

# 6) Harden ACLs
try {
    Write-Output "Removing inherited permissions..."
    icacls.exe $folderPath /inheritance:r | Out-Null

    Write-Output "Applying allow ACEs: Administrators = Full, Users = RX"
    icacls.exe $folderPath /grant "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null

    Write-Output "Applying DENY write for SYSTEM (prevents SYSTEM writing to this folder)"
    icacls.exe $folderPath /deny "SYSTEM:(OI)(CI)W" | Out-Null

    $aclOut = icacls.exe $folderPath
    Write-Output "Current ACL for ${folderPath}:`n$aclOut"
} catch {
    Write-Output "Failed to set ACLs: $_"
}

# 7) Set read-only attribute (visual)
try {
    attrib +r "$folderPath"
    Write-Output "Set Read-only attribute on folder."
} catch {
    Write-Output "Failed to set folder attribute: $_"
}

Write-Output "=== TPQM Hardening Script Completed: $(Get-Date) ==="

# ------------- Revert commands (if you need to undo) ----------------
# icacls "C:\Program Files (x86)\Lenovo\TPQM" /remove:d "SYSTEM"
# icacls "C:\Program Files (x86)\Lenovo\TPQM" /grant "SYSTEM:(OI)(CI)F"
# icacls "C:\Program Files (x86)\Lenovo\TPQM" /inheritance:e
