# Suspend-BitLocker

## Scripts
- `Suspend-BitLocker.ps1`: Suspends BitLocker protection on a target volume.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Suspend-BitLocker.ps1`
- Synopsis: Suspends BitLocker protection on a target volume.
- Description: Suspends BitLocker for a specified volume (default C:) and reports status before/after. Designed for local admin/SYSTEM execution (e.g., Intune remediations, runbooks, packaging tasks).
