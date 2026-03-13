# AP-Hash_FIx

## Scripts
- `AP-Hash_FIx.ps1`: Manages Autopilot hash retrieval remediation scripts for devices with hash-related issues.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `AP-Hash_FIx.ps1`
- Synopsis: Manages Autopilot hash retrieval remediation scripts for devices with hash-related issues.
- Description: This script automates the management of Autopilot hash retrieval remediation scripts in Intune. It identifies Autopilot devices that have remediation states other than 'noRemediationRequired' and ensures appropriate remediation scripts are created for hash retrieval. The script also performs cleanup by removing stale remediation scripts for devices that no longer require hash remediation. Key functions: - Identifies Autopilot devices with hash-related issues - Creates remediation scripts for devices missing hash retrieval remediation - Removes outdated remediation scripts for devices that no longer need them The remediation script naming convention follows: _invCmd_<datetime>_<serialNumber>_getAutopilotHash.
