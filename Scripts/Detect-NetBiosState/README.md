# Detect-NetBiosState

## Scripts
- `Detect-NetBiosState.ps1`: Checks the state of NetBIOS over TCP/IP on the active network adapter.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-NetBiosState.ps1`
- Synopsis: Checks the state of NetBIOS over TCP/IP on the active network adapter.
- Description: Determines the active network adapter, reads the TcpipNetbiosOptions value from Win32_NetworkAdapterConfiguration, logs the result and returns exit codes: 0 = compliant (NetBIOS disabled), 1 = non-compliant or error.
