# Intune-SetGroupTag

## Scripts
- `Intune-SetGroupTag.ps1`: Bulk updates Windows Autopilot device Group Tags from a CSV file using Microsoft Graph.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Intune-SetGroupTag.ps1`
- Synopsis: Bulk updates Windows Autopilot device Group Tags from a CSV file using Microsoft Graph.
- Description: This script connects to Microsoft Graph and updates the Group Tag property of Windows Autopilot device identities based on serial numbers supplied in a CSV file. It will: - Read serial numbers from a CSV file (either with or without a header row). - Query each serial in Microsoft Intune�s Autopilot device list. - Update the GroupTag property for matching devices. - Report the number of successful and failed updates.
