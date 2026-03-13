param(
    [string]$DeviceNamePattern = 'Intel*Wireless*Bluetooth*'
)

$ErrorActionPreference = 'Stop'

$statePath = 'HKLM:\SOFTWARE\Highspring\DriverRollback\IntelWirelessBluetooth'

function Get-MarkerName {
    param([string]$InstanceId)
    return 'v_' + ($InstanceId -replace '[^A-Za-z0-9]', '_')
}

function Get-IntelBluetoothDevices {
    param([string]$Pattern)

    $pnp = Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction Stop |
        Where-Object { $_.FriendlyName -like $Pattern }

    if (-not $pnp) { return @() }

    $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop
    $driverById = @{}
    foreach ($driver in $drivers) {
        if ($driver.DeviceID -and -not $driverById.ContainsKey($driver.DeviceID)) {
            $driverById[$driver.DeviceID] = $driver
        }
    }

    $result = @()
    foreach ($device in $pnp) {
        $driver = $null
        if ($driverById.ContainsKey($device.InstanceId)) {
            $driver = $driverById[$device.InstanceId]
        }

        $result += [pscustomobject]@{
            FriendlyName = $device.FriendlyName
            InstanceId = $device.InstanceId
            DriverVersion = if ($driver) { [string]$driver.DriverVersion } else { '' }
        }
    }

    return $result
}

$targets = Get-IntelBluetoothDevices -Pattern $DeviceNamePattern
if (-not $targets -or $targets.Count -eq 0) {
    Write-Output "Compliant: no present Bluetooth devices matched pattern '$DeviceNamePattern'."
    exit 0
}

$state = $null
if (Test-Path -Path $statePath) {
    $state = Get-ItemProperty -Path $statePath -ErrorAction SilentlyContinue
}

$needsRemediation = @()

foreach ($target in $targets) {
    $markerName = Get-MarkerName -InstanceId $target.InstanceId
    $storedVersion = if ($state -and $state.PSObject.Properties.Name -contains $markerName) {
        [string]$state.$markerName
    } else {
        ''
    }

    if ([string]::IsNullOrWhiteSpace($storedVersion) -or $storedVersion -ne $target.DriverVersion) {
        $needsRemediation += $target
    }
}

if ($needsRemediation.Count -gt 0) {
    Write-Output 'Non-compliant: Intel Wireless Bluetooth rollback required for device(s):'
    $needsRemediation | ForEach-Object {
        Write-Output " - $($_.FriendlyName) | Version=$($_.DriverVersion) | InstanceId=$($_.InstanceId)"
    }
    exit 1
}

Write-Output 'Compliant: Intel Wireless Bluetooth driver state matches remediation marker.'
exit 0
