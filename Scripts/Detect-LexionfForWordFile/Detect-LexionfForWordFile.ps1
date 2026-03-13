# ...existing code...
# Author: Tyler Cox
# Description: Detection script for folders in %LocalAppData%\Microsoft\Office\16.0\Wef
#              containing "Av1Zivj92J17X2Q3Yv+Ejg==" in the name.
# Version: 1.1 (with logging)

$basePath = Join-Path $env:LocalAppData 'Microsoft\Office\16.0\Wef'

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$logFile = Join-Path $logDir "Lexion_for_Word_Detection_$timestamp.log"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $logFile -Value "[$ts] [DETECTION] $Message"
}

Write-Log "Starting detection script."

$found = $false

if (Test-Path $basePath) {
    $folders = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*Av1Zivj92J17X2Q3Yv+Ejg==*' }

    if ($folders) {
        Write-Log "Found folder(s) matching pattern:"
        $folders | ForEach-Object { Write-Log " - $($_.FullName)" }
        $found = $true
    } else {
        Write-Log "No folders found matching pattern."
    }
} else {
    Write-Log "Base path not found: $basePath"
}

if ($found) {
    Write-Log "Detection result: NON-COMPLIANT"
    exit 1
} else {
    Write-Log "Detection result: COMPLIANT"
    exit 0
}