#Requires -Version 5.1
<#
.SYNOPSIS
    Removes Dell SupportAssist from the system.

.DESCRIPTION
    Removes Dell SupportAssist (MSI/EXE-based) and DellInc.DellSupportAssistforPCs (UWP) if present.

.NOTES
Author: Tyler Cox
Created: 2025-10-03
Blog: blog.tylercox.tech
#>

[CmdletBinding()]
param ()

# --- Logging setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir   = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation'
$logFile  = Join-Path $logDir "Detect-NetPowerSave_$timestamp.log"

if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

Start-Transcript -Path $logFile -Append | Out-Null
Write-Host "[Info] Logging started at $(Get-Date) - Log file: $logFile"

# --- Helper Function ---
function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Verify elevation ---
if (-not (Test-IsElevated)) {
    Write-Host "[Error] Access Denied. Please run with Administrator privileges."
    Stop-Transcript | Out-Null
    exit 1
}

# --- MSI/EXE Uninstall (Registry-based installs) ---
$TargetApps = @(
    'Dell SupportAssist',
    'Dell SupportAssist Remediation',
    'Dell SupportAssist OS Recovery',
    'SupportAssist Recovery Assistant',
    'Dell SupportAssist OS Recovery Plugin for Dell Update',
    'Dell SupportAssistAgent',
    'Dell Update - SupportAssist Update Plugin'
)

Write-Host "[Info] Searching registry for Dell SupportAssist components..."

$DellSA = Get-ItemProperty -Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $TargetApps -contains $_.DisplayName } |
    Select-Object -Property DisplayName, UninstallString

if ($DellSA) {
    foreach ($App in $DellSA) {
        Write-Host "[Info] Found $($App.DisplayName)"

        if ($App.UninstallString -match 'msiexec.exe') {
            $null = $App.UninstallString -match '{[A-F0-9-]+}'
            $guid = $matches[0]

            Write-Host "[Info] Removing $($App.DisplayName) using msiexec"
            try {
                $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $($guid) /qn /norestart" -Wait -PassThru
                if ($Process.ExitCode -ne 0) { throw $Process.ExitCode }
                Write-Host "[Info] Successfully removed $($App.DisplayName)"
            }
            catch {
                Write-Host "[Error] Failed removing $($App.DisplayName). Exit Code: $($Process.ExitCode)"
            }
        }
        elseif ($App.UninstallString -match 'SupportAssistUninstaller.exe') {
            Write-Host "[Info] Removing $($App.DisplayName) using SupportAssistUninstaller.exe"
            try {
                $Process = Start-Process -FilePath "$($App.UninstallString)" -ArgumentList "/arp /S /norestart" -Wait -PassThru
                if ($Process.ExitCode -ne 0) { throw $Process.ExitCode }
                Write-Host "[Info] Successfully removed $($App.DisplayName)"
            }
            catch {
                Write-Host "[Error] Failed removing $($App.DisplayName). Exit Code: $($Process.ExitCode)"
            }
        }
        else {
            Write-Host "[Warn] Unsupported uninstall method for $($App.DisplayName)"
        }
    }
}
else {
    Write-Host "[Info] No MSI/EXE-based Dell SupportAssist installations found."
}

# --- UWP Uninstall (Microsoft Store Appx installs) ---
$UWP = Get-AppxPackage -Name DellInc.DellSupportAssistforPCs -AllUsers -ErrorAction SilentlyContinue
if ($UWP) {
    Write-Host "[Info] Found DellInc.DellSupportAssistforPCs (UWP). Removing..."
    try {
        Remove-AppxPackage -Package $UWP.PackageFullName -AllUsers -ErrorAction Stop
        Write-Host "[Info] DellInc.DellSupportAssistforPCs successfully removed"
    }
    catch {
        Write-Host "[Error] Failed to remove DellInc.DellSupportAssistforPCs"
    }
}
else {
    Write-Host "[Info] No UWP Dell SupportAssist package found."
}

# --- Stop leftover process if still running ---
$SupportAssistClientUI = Get-Process -Name "SupportAssistClientUI" -ErrorAction SilentlyContinue
if ($SupportAssistClientUI) {
    Write-Host "[Info] SupportAssistClientUI still running. Stopping process..."
    try {
        $SupportAssistClientUI | Stop-Process -Force -Confirm:$false -ErrorAction Stop
        Write-Host "[Info] Process SupportAssistClientUI stopped successfully."
    }
    catch {
        Write-Host "[Warn] Failed to stop SupportAssistClientUI. A reboot may be required."
    }
}

Write-Host "[Info] Dell SupportAssist cleanup complete"
Stop-Transcript | Out-Null
exit 0