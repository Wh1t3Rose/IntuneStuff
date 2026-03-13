# Detect-BitlockerFDE

## Scripts
- `Detect-BitlockerFDE.ps1`: Detects whether a BitLocker full-disk encryption (FDE) policy registry key exists.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-BitlockerFDE.ps1`
- Synopsis: Detects whether a BitLocker full-disk encryption (FDE) policy registry key exists.
- Description: Checks for the presence of the Group Policy registry key used for BitLocker (FVE) policies. Presence of the key HKLM:\SOFTWARE\Policies\Microsoft\FVE typically indicates that a BitLocker FDE policy has been configured.
