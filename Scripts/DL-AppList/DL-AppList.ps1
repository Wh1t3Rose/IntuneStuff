<#
.SYNOPSIS
Exports all Windows applications from Microsoft Intune along with their App IDs and metadata to a CSV file.

.DESCRIPTION
This script connects to Microsoft Graph, retrieves all Windows-related mobile apps from Intune,
and exports relevant details including Display Name, App ID, Publisher, App Type, and assignment status.
Execution logs are written to the Intune Management Extension diagnostics directory.

Author: Tyler Cox
Version: 1.0.0
Date: 2026-02-16

CHANGELOG
1.0.0 - Initial production release

CREDITS
Developed for enterprise Intune administration and auditing.
#>

#region Configuration

$LogDirectory = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$CsvPath = Join-Path $LogDirectory "Intune-WindowsApps.csv"
$LogPath = Join-Path $LogDirectory "Intune-WindowsApps-Export.log"

#endregion

#region Logging Function

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Entry = "$Timestamp [$Level] $Message"

    Write-Output $Entry
    Add-Content -Path $LogPath -Value $Entry
}

#endregion

try {
    Write-Log "========== Script Execution Started =========="

    # Ensure Microsoft Graph Module
    try {
        Import-Module Microsoft.Graph.Devices.CorporateManagement -ErrorAction Stop
    }
    catch {
        Write-Log "Microsoft.Graph.Devices.CorporateManagement module required but not installed" "ERROR"
        exit 1
    }

    Write-Log "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -UseDeviceAuthentication -NoWelcome -ErrorAction Stop

    Write-Log "Retrieving mobile applications from Intune..."
    $AllApps = Get-MgDeviceAppManagementMobileApp -All -ErrorAction Stop

    Write-Log "Filtering Windows application types..."
    $WindowsApps = $AllApps | Where-Object {
        $_.'@odata.type' -match "win32LobApp|winGetApp|webApp|officeSuiteApp|microsoftStoreForBusinessApp"
    }

    Write-Log "Processing application data..."

    $ExportData = foreach ($App in $WindowsApps) {
        [PSCustomObject]@{
            DisplayName = $App.DisplayName
            AppId       = $App.Id
            AppType     = $App.'@odata.type'
            Publisher   = $App.Publisher
            IsAssigned  = $App.IsAssigned
        }
    }

    Write-Log "Exporting results to CSV: $CsvPath"
    $ExportData | Sort-Object DisplayName | Export-Csv -Path $CsvPath -NoTypeInformation -Force

    Write-Log "Export completed successfully. Total Windows Apps: $($ExportData.Count)"
    Write-Log "========== Script Execution Completed =========="

}
catch {
    Write-Log "An error occurred: $($_.Exception.Message)" "ERROR"
    Write-Log "========== Script Execution Failed ==========" "ERROR"
    exit 1
}
