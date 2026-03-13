# Detect-TPQM-4

## Scripts
- `Detect-TPQM-4.ps1`: Detects the presence of the Lenovo TPQM Assistant executable.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-TPQM-4.ps1`
- Synopsis: Detects the presence of the Lenovo TPQM Assistant executable.
- Description: This detection script checks whether the Lenovo TPQM Assistant executable (`TPQMAssistant.exe`) exists at the expected installation path: `C:\Program Files (x86)\Lenovo\TPQM\Assistant\TPQMAssistant.exe`. It returns exit code `1` if the file is found (non-compliant), and `0` if not found (compliant).
