# Get-EntraMFAGroupBypassAudit

## Scripts
- `Get-EntraMFAGroupBypassAudit.ps1`: Reports users that have remained in an Entra Conditional Access MFA Exclusion Group longer than a defined threshold.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Get-EntraMFAGroupBypassAudit.ps1`
- Synopsis: Reports users that have remained in an Entra Conditional Access MFA Exclusion Group longer than a defined threshold.
- Description: This runbook checks Entra ID audit logs to determine when users were added to a specified MFA exclusion group. If a user has remained in the group longer than the configured threshold (default 8 hours), the script sends an email report listing those users. Designed to run in Azure Automation using a Managed Identity.
