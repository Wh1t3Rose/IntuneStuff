# Get-EventViewerLog

## Scripts
- `Get-EventViewerLog.ps1`: Collects recent critical and error events from Windows Event Logs.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Get-EventViewerLog.ps1`
- Synopsis: Collects recent critical and error events from Windows Event Logs.
- Description: Retrieves the last 50 Critical and Error events from System and Application logs, saving them to a timestamped file in the Intune "Collect Diagnostics" folder.
