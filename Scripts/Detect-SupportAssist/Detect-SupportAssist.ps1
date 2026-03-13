#Requires -Version 5.1
<#
.SYNOPSIS
    Detection script for Dell SupportAssist and related apps
.DESCRIPTION
    Detects if Dell SupportAssist (classic MSI) or DellInc.DellSupportAssistforPCs (UWP) is installed.
    Returns exit code 1 if found, 0 if not.

.NOTES
Author: Tyler Cox
Created: C:\Users\TylerCox\OneDrive - Highspring\Packaging\!PS-Scripts\Detect-SupportAssist.ps1.CreationTime.ToString('yyyy-MM-dd')
Blog: blog.tylercox.tech
#>

[CmdletBinding()]
param()

# List of possible Dell SupportAssist-related product names (MSI/EXE installs)
$TargetApps = @(
    'Dell SupportAssist',
    'Dell SupportAssist Remediation',
    'Dell SupportAssist OS Recovery',
    'SupportAssist Recovery Assistant',
    'Dell SupportAssist OS Recovery Plugin for Dell Update',
    'Dell SupportAssistAgent',
    'Dell Update - SupportAssist Update Plugin'
)

# --- Check Registry (MSI/EXE installs) ---
$InstalledApps = Get-ItemProperty -Path `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
    -ErrorAction SilentlyContinue | Select-Object DisplayName

$RegistryMatch = $InstalledApps | Where-Object { $TargetApps -contains $_.DisplayName }

# --- Check Appx/UWP (Store installs like DellInc.DellSupportAssistforPCs) ---
$UWPMatch = Get-AppxPackage -Name DellInc.DellSupportAssistforPCs -ErrorAction SilentlyContinue

# --- Final Evaluation ---
if ($RegistryMatch -or $UWPMatch) {
    Write-Output "Dell SupportAssist detected"
    exit 1
}
else {
    Write-Output "Dell SupportAssist not detected"
    exit 0
}

