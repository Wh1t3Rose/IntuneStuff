# Detect-NetPowerSave

## Scripts
- `Detect-NetPowerSave.ps1`: Detects and reports network adapters with Idle Power Saving enabled.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-NetPowerSave.ps1`
- Synopsis: Detects and reports network adapters with Idle Power Saving enabled.
- Description: Queries advanced adapter properties for the 'Idle Power Saving' setting and identifies adapters with the registry value set to '1'. If any adapters are found, the script writes a message and exits non‑zero to indicate action is required; otherwise it writes a message and exits zero.
