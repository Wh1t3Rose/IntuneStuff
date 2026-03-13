# Detect-FailedWinUpgrades

## Scripts
- `Detect-FailedWinUpgrades.ps1`: Checks whether the system meets minimum Windows build and recent Monthly (B) Cumulative Update requirements.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-FailedWinUpgrades.ps1`
- Synopsis: Checks whether the system meets minimum Windows build and recent Monthly (B) Cumulative Update requirements.
- Description: Determines the local OS build and validates it against minimum required builds for Windows 10 and Windows 11. Then inspects the update history to find the most recent Monthly (B) Cumulative (security) update (KB5xxxxxx series) and calculates how many days have passed since it was installed. Flags non-compliance when the OS build is below the minimum or the last Monthly Cumulative update is older than 40 days.
