[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
	[string]$DeviceInstanceId,
	[string]$BluetoothNamePattern = 'Intel*Wireless*Bluetooth*',

	[switch]$IncludeNonPresentDevices
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
	$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
	return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
	throw 'This script must be run in an elevated PowerShell session (Run as Administrator).'
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

	public const uint DIGCF_DEFAULT = 0x00000001;
	public const uint DIGCF_PRESENT = 0x00000002;
	public const uint DIGCF_ALLCLASSES = 0x00000004;
	public const uint DIGCF_PROFILE = 0x00000008;
	public const uint DIGCF_DEVICEINTERFACE = 0x00000010;

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

function Resolve-TargetBluetoothDevice {
	param(
		[string]$RequestedDeviceInstanceId,
		[string]$NamePattern,
		[switch]$AllowNonPresent
	)

	if (-not (Get-Command -Name Get-PnpDevice -ErrorAction SilentlyContinue)) {
		throw 'Get-PnpDevice is not available on this system. Cannot auto-resolve Bluetooth target device.'
	}

	$bluetoothDevices = if ($AllowNonPresent) {
		Get-PnpDevice -Class Bluetooth -ErrorAction Stop
	} else {
		Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction Stop
	}

	if ($RequestedDeviceInstanceId) {
		$match = $bluetoothDevices | Where-Object { $_.InstanceId -eq $RequestedDeviceInstanceId } | Select-Object -First 1
		if (-not $match) {
			throw "Requested DeviceInstanceId was not found in Bluetooth class: $RequestedDeviceInstanceId"
		}
		if ($NamePattern -and $match.FriendlyName -notlike $NamePattern) {
			throw "Requested Bluetooth device '$($match.FriendlyName)' does not match required pattern '$NamePattern'."
		}
		return $match
	}

	$candidates = $bluetoothDevices | Where-Object { $_.FriendlyName -like $NamePattern }
	if (-not $candidates -or $candidates.Count -eq 0) {
		throw "No Bluetooth device matched pattern '$NamePattern'."
	}

	if ($candidates.Count -gt 1) {
		$list = $candidates | ForEach-Object { " - $($_.FriendlyName) :: $($_.InstanceId)" }
		throw "Multiple Bluetooth devices matched pattern '$NamePattern'. Provide -DeviceInstanceId explicitly.`n$($list -join "`n")"
	}

	return $candidates | Select-Object -First 1
}

$targetDevice = Resolve-TargetBluetoothDevice -RequestedDeviceInstanceId $DeviceInstanceId -NamePattern $BluetoothNamePattern -AllowNonPresent:$IncludeNonPresentDevices
$DeviceInstanceId = $targetDevice.InstanceId
$targetFriendlyName = if ($targetDevice.FriendlyName) { $targetDevice.FriendlyName } else { '<Unknown Bluetooth Device>' }

Write-Output "Target Bluetooth device: $targetFriendlyName"
Write-Output "Target InstanceId: $DeviceInstanceId"

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
			if ($last -eq 259) {
				break
			}
			throw "SetupDiEnumDeviceInfo failed at index $index. Win32Error=$last ($((Get-Win32ErrorMessage -Code $last)))."
		}

		$buffer = [System.Text.StringBuilder]::new(1024)
		$required = 0
		$idOk = [NativeDriverRollback]::SetupDiGetDeviceInstanceId($deviceInfoSet, [ref]$devInfo, $buffer, $buffer.Capacity, [ref]$required)
		if (-not $idOk) {
			$last = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
			Write-Verbose "Skipping index $index, could not read instance ID. Win32Error=$last"
			$index++
			continue
		}

		$foundId = $buffer.ToString()
		if ($foundId.Equals($DeviceInstanceId, [System.StringComparison]::OrdinalIgnoreCase)) {
			$targetDevInfo = $devInfo
			break
		}

		$index++
	}

	if ($null -eq $targetDevInfo) {
		throw "Device instance ID not found: $DeviceInstanceId"
	}

	$rebootRequired = $false
	$action = 'Rollback driver to previous package'
	$targetDisplay = "$targetFriendlyName ($DeviceInstanceId)"

	if ($PSCmdlet.ShouldProcess($targetDisplay, $action)) {
		$rollbackOk = [NativeDriverRollback]::DiRollbackDriver(
			$deviceInfoSet,
			[ref]$targetDevInfo,
			[IntPtr]::Zero,
			0,
			[ref]$rebootRequired
		)

		if (-not $rollbackOk) {
			$err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
			throw "DiRollbackDriver failed. Win32Error=$err ($((Get-Win32ErrorMessage -Code $err)))."
		}

		Write-Output "Rollback succeeded for device: $targetDisplay"
		Write-Output "RebootRequired: $rebootRequired"
	}
}
finally {
	[void][NativeDriverRollback]::SetupDiDestroyDeviceInfoList($deviceInfoSet)
}
