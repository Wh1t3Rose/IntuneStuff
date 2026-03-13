$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$zipPath = Get-ChildItem -Path $scriptDir -Filter '*.zip' | Select-Object -First 1

if (-not $zipPath) {
	throw "No .zip file found in $scriptDir"
}

$targetDir = 'C:\Oracle\Instant Client'
$logDir = 'C:\Windows\Software\Logs'
$logFile = Join-Path $logDir 'Oracle-Instant-Client-Install.log'

if (-not (Test-Path -Path $targetDir)) {
	New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -Path $logDir)) {
	New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

"[$(Get-Date -Format 's')] Extracting $($zipPath.FullName) to $targetDir" | Out-File -FilePath $logFile -Encoding ASCII -Append

Expand-Archive -Path $zipPath.FullName -DestinationPath $targetDir -Force

"[$(Get-Date -Format 's')] Extraction complete" | Out-File -FilePath $logFile -Encoding ASCII -Append
