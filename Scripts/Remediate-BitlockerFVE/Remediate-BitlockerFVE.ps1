<#
.SYNOPSIS
Brief description for Remediate-BitlockerFVE.ps1

.DESCRIPTION
Add a longer description for Remediate-BitlockerFVE.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Remediate-BitlockerFVE.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-10-08
Blog: blog.tylercox.tech
#>
# Remediation Script
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

if (Test-Path $RegPath) {
    try {
        Remove-Item -Path $RegPath -Recurse -Force
        Write-Output "Deleted registry key: $RegPath"
    }
    catch {
        Write-Output "Failed to delete $RegPath - $_"
    }
}
else {
    Write-Output "Registry key not found: $RegPath"
}



