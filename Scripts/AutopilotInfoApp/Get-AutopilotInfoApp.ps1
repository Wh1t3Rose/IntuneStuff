<#
.SYNOPSIS
Brief description for AutopilotInfoApp.ps1

.DESCRIPTION
Add a longer description for AutopilotInfoApp.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\AutopilotInfoApp.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-21
Blog: blog.tylercox.tech
#>
<#
.DESCRIPTION
    Reads and upload the Autopilot information from a device to Intune. 
.NOTES
Author: Tyler Cox
Created: 2025-09-21
#>

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
Write-Host "(i) We will now install the some required components`n" -ForegroundColor Cyan
Install-PackageProvider -Name NuGet -Force | Out-Null
Install-Script -Name Get-WindowsAutoPilotInfo -Force | Out-Null
Install-Module -Name WindowsAutopilotIntune -Force | Out-Null

$GroupTag = "Win11-Internal"

$AutopilotParams = @{
    Online = $true
    TenantId = ""
    AppId = ""
    AppSecret = ""
    GroupTag = "$GroupTag"
}

Get-WindowsAutoPilotInfo @AutopilotParams

Read-Host "Press Enter to exit"

Pause

shutdown -r -t 60
