<#
.SYNOPSIS
Brief description for Entra-Stale-Disable-List.ps1

.DESCRIPTION
Add a longer description for Entra-Stale-Disable-List.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Entra-Stale-Disable-List.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-15
Blog: blog.tylercox.tech
#>
# Install Microsoft Graph module if not already installed
# Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft Graph with required permissions
Connect-MgGraph -Scopes "Device.ReadWrite.All"

# Optional: Confirm which tenant you're connected to
Get-MgContext

# Read device Object IDs from the file (not hardware Device IDs)
$deviceObjectIds = Get-Content -Path "C:\Temp\125-Entra_MacMDM_before90dayss.txt" | ForEach-Object { $_.Trim() }

foreach ($deviceObjectId in $deviceObjectIds) {
    try {
        Write-Host "Checking if device exists: $deviceObjectId"

        # Try to get the device to ensure it exists
        $device = Get-MgDevice -DeviceId $deviceObjectId -ErrorAction Stop

        Write-Host "Disabling device: $($device.DisplayName) ($deviceObjectId)"

        # Disable the device by setting AccountEnabled to false
        Update-MgDevice -DeviceId $deviceObjectId -AccountEnabled:$false -ErrorAction Stop

        Write-Host "Successfully disabled $deviceObjectId`n"
    }
    catch {
        Write-Warning "Failed to disable $deviceObjectId. Error: $_"
    }
}



