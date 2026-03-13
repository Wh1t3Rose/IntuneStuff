# Detect-PersonalTeams

## Scripts
- `Detect-PersonalTeams.ps1`: Detects whether Microsoft Teams (personal / per-user install) is installed for the current user.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-PersonalTeams.ps1`
- Synopsis: Detects whether Microsoft Teams (personal / per-user install) is installed for the current user.
- Description: Checks the typical per-user Teams executable path under %LOCALAPPDATA%\Microsoft\Teams\current\Teams.exe and also queries Appx packages for a package named "MicrosoftTeams". If either is present the script indicates that Teams Personal is installed.
