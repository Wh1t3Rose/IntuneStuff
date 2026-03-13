# Detect-AlldotNetVersions-2

## Scripts
- `Detect-AlldotNetVersions-2.ps1`: Detects the installed .NET Framework 4.5+ version on the local machine.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-AlldotNetVersions-2.ps1`
- Synopsis: Detects the installed .NET Framework 4.5+ version on the local machine.
- Description: Reads the Release DWORD from: HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full Maps the Release value to a human-readable .NET Framework version. Logs the output to both console and a persistent log file.
