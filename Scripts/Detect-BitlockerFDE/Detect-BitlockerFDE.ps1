<#
.SYNOPSIS
Detects whether a BitLocker full-disk encryption (FDE) policy registry key exists.

.DESCRIPTION
Checks for the presence of the Group Policy registry key used for BitLocker
(FVE) policies. Presence of the key HKLM:\SOFTWARE\Policies\Microsoft\FVE
typically indicates that a BitLocker FDE policy has been configured.

.PARAMETER RegistryPath
Optional. Registry path to check for BitLocker FVE policy. Default:
'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

.EXAMPLE
.\Detect-BitlockerFDE.ps1
Checks the default registry path and writes whether the key exists.

.INPUTS
None.

.OUTPUTS
Writes a short status string to output and exits with code:
0 - compliant (key not found)
1 - non-compliant (key exists)

.NOTES
Author: Tyler Cox
Created: 2025-10-08
Blog: blog.tylercox.tech
#>
# ...existing code...
# Detection Script
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

if (Test-Path $RegPath) {
    Write-Output "Key exists: $RegPath"
    exit 1  # Non-compliant
}
else {
    Write-Output "Key not found: $RegPath"
    exit 0  # Compliant
}# Detection Script
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

if (Test-Path $RegPath) {
    Write-Output "Key exists: $RegPath"
    exit 1  # Non-compliant
}
else {
    Write-Output "Key not found: $RegPath"
    exit 0  # Compliant
}

