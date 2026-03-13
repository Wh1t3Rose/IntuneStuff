# Remediate-TPQM-4

## Scripts
- `Remediate-TPQM-4.ps1`: Hardens and remediates the Lenovo TPQM folder by killing related processes, removing old files, and reapplying secure permissions.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Remediate-TPQM-4.ps1`
- Synopsis: Hardens and remediates the Lenovo TPQM folder by killing related processes, removing old files, and reapplying secure permissions.
- Description: This script is designed to remove, rebuild, and harden the Lenovo TPQM folder (C:\Program Files (x86)\Lenovo\TPQM). It stops related processes and services, attempts uninstallation if applicable, deletes and recreates the folder, and applies restrictive ACLs to prevent SYSTEM from writing to it. Intended to run under SYSTEM context (e.g., via Intune remediation or scheduled task). All activity is logged to C:\ProgramData\IntuneLogs\TPQM_Remediation.log.
