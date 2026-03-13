[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$DeviceNamePattern = 'Intel*Wireless*Bluetooth*',
    [switch]$IncludeNonPresentDevices
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$statePath = 'HKLM:\SOFTWARE\Highspring\DriverRollback\IntelWirelessBluetooth'

function Get-MarkerName {
    param([string]$InstanceId)
    return 'v_' + ($InstanceId -replace '[^A-Za-z0-9]', '_')
}

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-StatePath {
    if (-not (Test-Path -Path $statePath)) {
        New-Item -Path $statePath -Force | Out-Null
    }
}

function Get-IntelBluetoothDevices {
    param([string]$Pattern)

    $pnp = if ($IncludeNonPresentDevices) {
        Get-PnpDevice -Class Bluetooth -ErrorAction Stop
    } else {
        Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction Stop
    }

    $pnp = $pnp | Where-Object { $_.FriendlyName -like $Pattern }
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

if (-not (Test-IsAdministrator)) {
    throw 'This script must run elevated (Administrator/SYSTEM).'
}

if (-not ('NativeDriverRollback' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeDriverRollback
{
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    public const uint DIGCF_PRESENT = 0x00000002;
    public const uint DIGCF_ALLCLASSES = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(
        IntPtr ClassGuid,
        string Enumerator,
        IntPtr hwndParent,
        uint Flags
    );

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetupDiEnumDeviceInfo(
        IntPtr DeviceInfoSet,
        uint MemberIndex,
        ref SP_DEVINFO_DATA DeviceInfoData
    );

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetupDiGetDeviceInstanceId(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        StringBuilder DeviceInstanceId,
        int DeviceInstanceIdSize,
        out int RequiredSize
    );

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

    [DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DiRollbackDriver(
        IntPtr DeviceInfoSet,
        ref SP_DEVINFO_DATA DeviceInfoData,
        IntPtr hwndParent,
        uint Flags,
        [MarshalAs(UnmanagedType.Bool)] out bool NeedReboot
    );
}
"@
}

function Get-Win32ErrorMessage {
    param([int]$Code)
    return ([System.ComponentModel.Win32Exception]::new($Code)).Message
}

function Invoke-RollbackByInstanceId {
    param([string]$InstanceId)

    $flags = [NativeDriverRollback]::DIGCF_ALLCLASSES
    if (-not $IncludeNonPresentDevices) {
        $flags = $flags -bor [NativeDriverRollback]::DIGCF_PRESENT
    }

    $deviceInfoSet = [NativeDriverRollback]::SetupDiGetClassDevs([IntPtr]::Zero, $null, [IntPtr]::Zero, $flags)
    if ($deviceInfoSet -eq [NativeDriverRollback]::INVALID_HANDLE_VALUE) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "SetupDiGetClassDevs failed. Win32Error=$err ($((Get-Win32ErrorMessage -Code $err)))."
    }

    try {
        $targetDevInfo = $null
        $index = 0

        while ($true) {
            $devInfo = [NativeDriverRollback+SP_DEVINFO_DATA]::new()
            $devInfo.cbSize = [uint32][Runtime.InteropServices.Marshal]::SizeOf([type][NativeDriverRollback+SP_DEVINFO_DATA])

            $enumOk = [NativeDriverRollback]::SetupDiEnumDeviceInfo($deviceInfoSet, [uint32]$index, [ref]$devInfo)
            if (-not $enumOk) {
                $last = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($last -eq 259) { break }
                throw "SetupDiEnumDeviceInfo failed at index $index. Win32Error=$last ($((Get-Win32ErrorMessage -Code $last)))."
            }

            $buffer = [System.Text.StringBuilder]::new(1024)
            $required = 0
            $idOk = [NativeDriverRollback]::SetupDiGetDeviceInstanceId($deviceInfoSet, [ref]$devInfo, $buffer, $buffer.Capacity, [ref]$required)
            if (-not $idOk) {
                $index++
                continue
            }

            $foundId = $buffer.ToString()
            if ($foundId.Equals($InstanceId, [System.StringComparison]::OrdinalIgnoreCase)) {
                $targetDevInfo = $devInfo
                break
            }

            $index++
        }

        if ($null -eq $targetDevInfo) {
            throw "Device instance ID not found for rollback: $InstanceId"
        }

        $needReboot = $false
        $ok = [NativeDriverRollback]::DiRollbackDriver(
            $deviceInfoSet,
            [ref]$targetDevInfo,
            [IntPtr]::Zero,
            0,
            [ref]$needReboot
        )

        if (-not $ok) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "DiRollbackDriver failed for $InstanceId. Win32Error=$err ($((Get-Win32ErrorMessage -Code $err)))."
        }

        return $needReboot
    }
    finally {
        [void][NativeDriverRollback]::SetupDiDestroyDeviceInfoList($deviceInfoSet)
    }
}

$targets = Get-IntelBluetoothDevices -Pattern $DeviceNamePattern
if (-not $targets -or $targets.Count -eq 0) {
    Write-Output "No matching Bluetooth devices found for pattern '$DeviceNamePattern'. Nothing to remediate."
    exit 0
}

Ensure-StatePath

$failed = @()
$rebootRequiredOverall = $false

foreach ($target in $targets) {
    $display = "$($target.FriendlyName) | $($target.InstanceId)"

    if ($PSCmdlet.ShouldProcess($display, 'Rollback Bluetooth driver')) {
        try {
            $needReboot = Invoke-RollbackByInstanceId -InstanceId $target.InstanceId
            if ($needReboot) { $rebootRequiredOverall = $true }

            $refreshed = Get-IntelBluetoothDevices -Pattern $DeviceNamePattern |
                Where-Object { $_.InstanceId -eq $target.InstanceId } |
                Select-Object -First 1

            $newVersion = if ($refreshed) { $refreshed.DriverVersion } else { $target.DriverVersion }
            $markerName = Get-MarkerName -InstanceId $target.InstanceId
            Set-ItemProperty -Path $statePath -Name $markerName -Value $newVersion -Type String -Force

            Write-Output "Rollback succeeded: $display"
            Write-Output "DriverVersion after remediation: $newVersion"
            Write-Output "RebootRequired for device: $needReboot"
        }
        catch {
            $failed += [pscustomobject]@{
                FriendlyName = $target.FriendlyName
                InstanceId = $target.InstanceId
                Error = $_.Exception.Message
            }
            Write-Output "Rollback failed: $display"
            Write-Output "Error: $($_.Exception.Message)"
        }
    }
}

if ($failed.Count -gt 0) {
    Write-Output 'Remediation finished with failures:'
    $failed | ForEach-Object {
        Write-Output " - $($_.FriendlyName) | $($_.InstanceId) | $($_.Error)"
    }
    exit 1
}

Write-Output "Remediation completed successfully. RebootRequiredAny=$rebootRequiredOverall"
exit 0
