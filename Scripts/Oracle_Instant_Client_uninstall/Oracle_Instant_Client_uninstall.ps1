$ErrorActionPreference = 'Stop'

$targetDir = 'C:\Oracle\Instant Client'
$logDir = 'C:\Windows\Software\Logs'
$logFile = Join-Path $logDir 'Oracle-Instant-Client-Uninstall.log'

if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

if (Test-Path -Path $targetDir) {
    "[$(Get-Date -Format 's')] Removing $targetDir" | Out-File -FilePath $logFile -Encoding ASCII -Append
    Remove-Item -Path $targetDir -Recurse -Force
    "[$(Get-Date -Format 's')] Removal complete" | Out-File -FilePath $logFile -Encoding ASCII -Append
} else {
    "[$(Get-Date -Format 's')] $targetDir not found" | Out-File -FilePath $logFile -Encoding ASCII -Append
}