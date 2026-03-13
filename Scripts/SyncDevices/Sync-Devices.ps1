# Author: Tyler Cox
# Purpose: Sync Intune devices listed in a CSV

# Install module if not already
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Connect to Intune Graph API
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All"

# Path to your CSV
$csvPath = "C:\temp\IntuneDevices.csv"

# Import CSV
$devices = Import-Csv -Path $csvPath

foreach ($device in $devices) {

    # Determine if CSV has DeviceId or DeviceName
    if ($device.PSObject.Properties.Name -contains "DeviceId") {
        $deviceId = $device.DeviceId
    } elseif ($device.PSObject.Properties.Name -contains "DeviceName") {
        # Lookup device ID by name
        $mgDevice = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$($device.DeviceName)'" -Top 1
        if ($mgDevice) {
            $deviceId = $mgDevice.Id
        } else {
            Write-Warning "Device not found: $($device.DeviceName)"
            continue
        }
    } else {
        Write-Warning "CSV must have DeviceId or DeviceName column."
        break
    }

    # Trigger sync
    try {
        Invoke-MgDeviceManagementManagedDeviceRemoteAction -ManagedDeviceId $deviceId -RemoteAction SyncDevice
        Write-Host "Sync triggered for device: $($device.DeviceName ?? $deviceId)"
    } catch {
        Write-Warning "Failed to sync device $($device.DeviceName ?? $deviceId): $_"
    }
}
