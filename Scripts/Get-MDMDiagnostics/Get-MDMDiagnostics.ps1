<#
.SYNOPSIS
Collects Autopilot and MDM diagnostics during OOBE.

.DESCRIPTION
Installs Get-AutopilotDiagnosticsCommunity, runs diagnostics, and exports
relevant logs for troubleshooting Autopilot and Intune MDM enrollment failures.

AUTHOR
Tyler Cox

VERSION
1.0

CHANGELOG
1.0 - Initial release

CREDITS
Get-AutopilotDiagnosticsCommunity by Michael Niehaus community contributors
#>

Write-Host "Starting Autopilot diagnostics collection..." -ForegroundColor Cyan

# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Create directories
$paths = @(
"C:\AutopilotDiagnostics",
"D:\AutopilotDiagnostics"
)

foreach ($path in $paths) {
    if (Test-Path ($path.Substring(0,2))) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Install NuGet provider
Write-Host "Installing NuGet provider..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null

# Trust PSGallery
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Install diagnostics script
Write-Host "Installing Get-AutopilotDiagnosticsCommunity..."
Install-Script -Name Get-AutopilotDiagnosticsCommunity -Force

# Run diagnostics
Write-Host "Running Autopilot diagnostics..."
$scriptPath = "$env:ProgramFiles\WindowsPowerShell\Scripts\Get-AutopilotDiagnosticsCommunity.ps1"

foreach ($path in $paths) {
    if (Test-Path ($path.Substring(0,2))) {
        & $scriptPath -Online -OutputFile "$path\AutopilotCommunityDiagnostics.txt"
    }
}

# Export key event logs
$logs = @(
"Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
"Microsoft-Windows-AAD/Operational",
"Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin"
)

foreach ($log in $logs) {
    foreach ($path in $paths) {
        if (Test-Path ($path.Substring(0,2))) {

            $safeName = $log.Replace("/","-")

            Write-Host "Exporting $log to $path..."

            Get-WinEvent -LogName $log -ErrorAction SilentlyContinue |
            Select TimeCreated, Id, LevelDisplayName, Message |
            Out-File "$path\$safeName.txt"
        }
    }
}

# Export dsregcmd status
foreach ($path in $paths) {
    if (Test-Path ($path.Substring(0,2))) {

        Write-Host "Collecting Azure AD join status..."

        dsregcmd /status | Out-File "$path\dsregcmd_status.txt"
    }
}

Write-Host ""
Write-Host "Diagnostics complete." -ForegroundColor Green
Write-Host "Logs saved to:"
Write-Host "C:\AutopilotDiagnostics"
Write-Host "D:\AutopilotDiagnostics (if available)"