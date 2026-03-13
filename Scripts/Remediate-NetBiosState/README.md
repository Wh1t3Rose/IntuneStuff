# Remediate-NetBiosState

## Scripts
- `Remediate-NetBiosState.ps1`: This script checks the state of NetBIOS over TCP/IP on the active network adapter and attempts to disable it if it's not already.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Remediate-NetBiosState.ps1`
- Synopsis: This script checks the state of NetBIOS over TCP/IP on the active network adapter and attempts to disable it if it's not already.
- Description: The script defines two functions, Get-ActiveNetworkCard and Get-NetBiosState. Get-ActiveNetworkCard retrieves the description of the active network interface card (NIC). Get-NetBiosState retrieves the current NetBIOS over TCP/IP setting for the active NIC. The script then checks if NetBIOS is disabled. If it is not, it attempts to disable it and outputs a success message if successful, or an error message if not.
