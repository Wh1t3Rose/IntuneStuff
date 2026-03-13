# Author: Tyler Cox
# Description: Remediation script to remove folders in %LocalAppData%\Microsoft\Office\16.0\Wef
#              containing "Av1Zivj92J17X2Q3Yv+Ejg==", with fresh logging each run.
# Version: 1.2

$basePath = Join-Path $env:LocalAppData 'Microsoft\Office\16.0\Wef'
$logDir = "C:\ProgramData\IntuneRemediationLogs"
$logFile = "$logDir\LexionRemoval.log"

# Ensure log directory exists
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Remove existing log file if it exists
if (Test-Path $logFile) {
    Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
}

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $logFile -Value "[$timestamp] [REMEDIATION] $Message"
}

Write-Log "Starting remediation script."

if (Test-Path $basePath) {
    $folders = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*Av1Zivj92J17X2Q3Yv+Ejg==*" }

    if ($folders) {
        foreach ($folder in $folders) {
            try {
                Write-Log "Attempting to delete: $($folder.FullName)"
                Remove-Item -LiteralPath $folder.FullName -Recurse -Force -ErrorAction Stop
                Write-Log "Deleted successfully: $($folder.FullName)"
            }
            catch {
                Write-Log "Failed to delete $($folder.FullName): $($_.Exception.Message)"
            }
        }
        Write-Log "Remediation complete. Removed $($folders.Count) folder(s)."
    } else {
        Write-Log "No matching folders found for deletion."
    }
} else {
    Write-Log "Base path not found: $basePath"
}

Write-Log "Remediation script finished."
