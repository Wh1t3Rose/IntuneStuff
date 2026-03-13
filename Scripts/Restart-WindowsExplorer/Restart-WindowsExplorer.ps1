<#
.SYNOPSIS
    Restarts Windows Explorer to fix UI issues.
.DESCRIPTION
    Kills and restarts explorer.exe to resolve taskbar, Start menu, or desktop glitches.
.AUTHOR
    Tyler Cox
#>

$LogDirectory = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation"
$LogFile = Join-Path $LogDirectory "RestartExplorer.log"
if (!(Test-Path $LogDirectory)) { New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null }

Start-Transcript -Path $LogFile -Append

Write-Host "Restarting Windows Explorer..."
try {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process explorer.exe
    Write-Host "Explorer restarted successfully."
} catch {
    Write-Warning "Failed to restart Explorer: $($_.Exception.Message)"
}

Stop-Transcript
Write-Host "Log saved to: $LogFile"
exit 0
