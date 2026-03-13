# Detect-TPQM

## Scripts
- `Detect-TPQM.ps1`: Detects if "TrackPoint Quick Menu" (Lenovo) is installed.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-TPQM.ps1`
- Synopsis: Detects if "TrackPoint Quick Menu" (Lenovo) is installed.
- Description: Searches Appx packages, registry uninstall keys, and winget list. Returns exit code 1 if found (non-compliant), 0 if not present.
