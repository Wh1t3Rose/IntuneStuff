<#
.SYNOPSIS
Brief description for Remediate-NetPowerSave.ps1

.DESCRIPTION
Add a longer description for Remediate-NetPowerSave.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Remediate-NetPowerSave.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-10-17
Blog: blog.tylercox.tech
#>
$adapters = Get-NetAdapterAdvancedProperty -DisplayName 'Idle Power Saving' | Where-Object RegistryValue -eq '1'
foreach ($adapter in $adapters) {
    Set-NetAdapterAdvancedProperty -InterfaceDescription $adapter.InterfaceDescription -DisplayName 'Idle Power Saving' -RegistryValue '0'
}


