# Remediate-TPQM

## Scripts
- `Remediate-TPQM.ps1`: Removes "TrackPoint Quick Menu" (Lenovo) from device.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Remediate-TPQM.ps1`
- Synopsis: Removes "TrackPoint Quick Menu" (Lenovo) from device.
- Description: Attempts to remove Appx/msix, registry-based uninstallers, and winget entries. Logs results to C:\Windows\Temp\TrackPointQuickMenu_Remediation.log.
