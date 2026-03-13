# Detect-UptimeOver72Hours

## Scripts
- `Detect-UptimeOver72Hours.ps1`: Intune remediation detection script for device uptime threshold.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-UptimeOver72Hours.ps1`
- Synopsis: Intune remediation detection script for device uptime threshold.
- Description: Checks device uptime based on last boot time. If uptime is greater than 72 hours, returns "With Issue" and exits 1. Otherwise returns "No Issue" and exits 0.
