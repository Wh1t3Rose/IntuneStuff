<#
.SYNOPSIS
Brief description for Intune-90day-Cleanup-List.ps1

.DESCRIPTION
Add a longer description for Intune-90day-Cleanup-List.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Intune-90day-Cleanup-List.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-15
Blog: blog.tylercox.tech
#>
# Requires Microsoft.Graph module
# Install if needed:
# Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Graph with required permissions
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All"

# Import your list of Device IDs (one per line in DeviceIDs.txt)
$DeviceIds = Get-Content "C:\Temp\364-Entra_Unknown_OS_before90days.txt"

foreach ($DeviceId in $DeviceIds) {
    try {
        Write-Host "Attempting to delete Intune device with ID: $DeviceId"
        
        Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $DeviceId -ErrorAction Stop
        
        Write-Host "Successfully deleted device $DeviceId" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to delete device $DeviceId. Error: $_" -ForegroundColor Red
    }
}


