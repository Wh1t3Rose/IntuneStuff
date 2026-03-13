<#
.SYNOPSIS
    Collects recent critical and error events from Windows Event Logs.
.DESCRIPTION
    Retrieves the last 50 Critical and Error events from System and Application logs,
    saving them to a timestamped file in the Intune "Collect Diagnostics" folder.
.AUTHOR
    Tyler Cox
#>

$LogDirectory = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation"
if (!(Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$LogFile = Join-Path $LogDirectory "QuickEventLog_$Timestamp.log"

function Write-Info($Message) {
    $Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "$Time  $Message"
}

Write-Info "Collecting recent Critical and Error events from System and Application logs..."
Start-Transcript -Path $LogFile -Append

try {
    $SystemEvents = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error", "Critical") } |
        Select-Object -First 50 -Property TimeCreated, LevelDisplayName, Source, Id, Message

    $AppEvents = Get-WinEvent -LogName Application -ErrorAction SilentlyContinue |
        Where-Object { $_.LevelDisplayName -in @("Error", "Critical") } |
        Select-Object -First 50 -Property TimeCreated, LevelDisplayName, Source, Id, Message

    Write-Host "`n=== SYSTEM LOG EVENTS ==="
    $SystemEvents | Format-Table -AutoSize

    Write-Host "`n=== APPLICATION LOG EVENTS ==="
    $AppEvents | Format-Table -AutoSize

    Write-Host "`nWriting detailed logs to: $LogFile"
    "`n=== SYSTEM LOG EVENTS ===" | Out-File -FilePath $LogFile -Append
    $SystemEvents | Format-Table -AutoSize | Out-File -FilePath $LogFile -Append
    "`n=== APPLICATION LOG EVENTS ===" | Out-File -FilePath $LogFile -Append
    $AppEvents | Format-Table -AutoSize | Out-File -FilePath $LogFile -Append

    Write-Info "Event log collection complete."
} catch {
    Write-Warning "Error collecting event logs: $($_.Exception.Message)"
}

Stop-Transcript
Write-Host "Log saved to: $LogFile"
exit 0
