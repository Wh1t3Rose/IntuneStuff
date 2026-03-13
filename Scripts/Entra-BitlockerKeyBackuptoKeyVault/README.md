# Entra-BitlockerKeyBackuptoKeyVault

## Scripts
- `Entra-BitlockerKeyBackuptoKeyVault.ps1`: Backs up BitLocker recovery keys from Entra ID (Azure AD) to Azure Key Vault using REST API.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Entra-BitlockerKeyBackuptoKeyVault.ps1`
- Synopsis: Backs up BitLocker recovery keys from Entra ID (Azure AD) to Azure Key Vault using REST API.
- Description: This script connects to Microsoft Graph API to retrieve BitLocker recovery keys for Windows devices, then stores them securely in Azure Key Vault using REST API. Each key is stored as a secret with device information (name and serial number) included in tags. The script ensures secure storage The script uses Microsoft Graph authentication for both Graph API and Key Vault API calls, eliminating the need for the large Az.Accounts module. Simply provide your Key Vault URI and the script handles the rest. On first run, you will be prompted to consent to the required permissions including Key Vault access.
