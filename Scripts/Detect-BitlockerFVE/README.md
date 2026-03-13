# Detect-BitlockerFVE

## Scripts
- `Detect-BitlockerFVE.ps1`: Detects whether a BitLocker full-disk encryption (FVE) Group Policy registry key exists.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-BitlockerFVE.ps1`
- Synopsis: Detects whether a BitLocker full-disk encryption (FVE) Group Policy registry key exists.
- Description: Checks for the presence of the Group Policy registry key used for BitLocker (FVE) policies. Presence of HKLM:\SOFTWARE\Policies\Microsoft\FVE typically indicates that a BitLocker FDE policy has been configured via Group Policy.
